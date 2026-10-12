#!/usr/bin/env python3
"""
exposure_audit.py  v0.1.0

Measures what an unprivileged process launched from THIS terminal could silently
read or use -- the position a malicious package install script (Shai-Hulud style)
would be in.

Design rules
  * Offline: no network modules, no tools that phone home.
  * Never stores or prints secret values. Only paths, counts, and salted
    fingerprints (HMAC with a per-machine salt, useless off this machine).
  * Read-only, except for its own state in ~/.exposure-audit (mode 0700).
  * Python 3.9+ standard library only.

Run it from each terminal / IDE terminal you actually install packages from:
    python3 exposure_audit.py            # audit, write report, print summary
    python3 exposure_audit.py --open     # ...and open the HTML report
    python3 exposure_audit.py --no-folder-probe   # never risk a macOS consent prompt
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import html
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

VERSION = "0.1.0"
HOME = Path.home()
STATE = HOME / ".exposure-audit"
IS_MAC = sys.platform == "darwin"
NOW = time.time()

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def tilde(p):
    s = str(p)
    h = str(HOME)
    return "~" + s[len(h):] if s.startswith(h) else s


def read_text(p, limit=2_000_000):
    try:
        with open(p, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None


def run(cmd, timeout=10):
    """Run a local binary. Returns (returncode, stdout) or (None, '') on failure."""
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL, timeout=timeout)
        return r.returncode, r.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return None, ""


def load_salt():
    STATE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE, 0o700)
    sp = STATE / "salt"
    if not sp.exists():
        fd = os.open(sp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    return sp.read_bytes()


SALT = b""


def fp(secret):
    return hmac.new(SALT, secret.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]


def age_days(p):
    try:
        return int((NOW - os.stat(p).st_mtime) // 86400)
    except OSError:
        return None


def others_can_read(p):
    try:
        return bool(os.stat(p).st_mode & 0o044)
    except OSError:
        return False


# --------------------------------------------------------------------------
# secret recognition (values are only ever hashed, never kept)
# --------------------------------------------------------------------------

TOKEN_RX = [  # (class, pattern)
    ("propagation", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("propagation", r"github_pat_[A-Za-z0-9_]{40,}"),
    ("propagation", r"npm_[A-Za-z0-9]{36}"),
    ("propagation", r"pypi-AgEI[A-Za-z0-9_\-]{40,}"),
    ("propagation", r"glpat-[A-Za-z0-9_\-]{20,}"),
    ("cloud", r"A[KS]IA[0-9A-Z]{16}"),
    ("cloud", r"AIza[0-9A-Za-z_\-]{35}"),
    ("cloud", r"dop_v1_[a-f0-9]{64}"),
    ("service", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("service", r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}"),
    ("service", r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    ("service", r"sk_live_[A-Za-z0-9]{20,}"),
    ("service", r"hf_[A-Za-z0-9]{30,}"),
    ("service", r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),
    ("service", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
TOKEN_RX = [(k, re.compile(p)) for k, p in TOKEN_RX]

SECRET_NAME = r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_\-]?KEY|ACCESS[_\-]?KEY|PRIVATE[_\-]?KEY|CREDENTIAL|AUTH)"
SECRET_NAME_RX = re.compile(SECRET_NAME, re.I)
KV_RX = re.compile(
    r"""["']?([A-Za-z0-9_.\-]*""" + SECRET_NAME + r"""[A-Za-z0-9_.\-]*)["']?\s*[:=]\s*["']?([^\s"',;}{]{8,})""",
    re.I)
PLACEHOLDER_RX = re.compile(
    r"^(?:\$|<|\{\{|%|your|xxx+|changeme|example|placeholder|todo|none|null|true|false|undefined|password|secret|\*+)",
    re.I)
PROP_NAME_RX = re.compile(r"NPM|NODE_AUTH|GITHUB|GH_|GITLAB|PYPI|TWINE|CARGO|RUBYGEMS", re.I)
CLOUD_NAME_RX = re.compile(r"AWS|GOOGLE|GCP|GCLOUD|CLOUDSDK|AZURE|ARM_|DIGITALOCEAN|CLOUDFLARE|KUBE|TF_|VAULT", re.I)
RANK = {"generic": 0, "service": 1, "cloud": 2, "propagation": 3}


def looks_real(v):
    v = v.strip()
    if len(v) < 8 or PLACEHOLDER_RX.match(v):
        return False
    if len(set(v)) < 5:
        return False
    return True


def klass_for_name(name):
    if PROP_NAME_RX.search(name):
        return "propagation"
    if CLOUD_NAME_RX.search(name):
        return "cloud"
    return "generic"


def extract_generic(text):
    """Return {secret_value: class} found in free text. Values never leave this process."""
    out = {}
    for k, rx in TOKEN_RX:
        for m in rx.finditer(text):
            out[m.group(0)] = k
    for m in KV_RX.finditer(text):
        name, val = m.group(1), m.group(2)
        if looks_real(val) and not val.startswith(("/", "~", "http://", "https://")):
            k = klass_for_name(name)
            if RANK[k] > RANK.get(out.get(val, "generic"), -1) or val not in out:
                out[val] = max(k, out.get(val, k), key=lambda c: RANK[c])
    return out


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------

FINDINGS = []
ERRORS = []

BASE = {"propagation": 10, "cloud": 8, "service": 5, "generic": 3}
KLASS_LABEL = {"propagation": "Worm vector", "cloud": "Cloud / infra",
               "service": "Service token", "generic": "Unclassified secret"}

FIX = {
    "npm": "Publish with npm trusted publishing (OIDC) so no token lives on disk; if you must keep one, make it granular, read-only, and short-lived. Set ignore-scripts=true.",
    "registry": "Use the registry's trusted-publisher (OIDC) flow from CI and delete the local upload token.",
    "github": "Keep the token in the Keychain behind an app-gated helper, or use a fine-grained token with minimal repo scope and an expiry. Remove plaintext copies.",
    "ssh-plain": "Move this key into the Secure Enclave (Secretive) or a password-manager SSH agent that asks per use. At minimum add a passphrase.",
    "ssh-agent": "Use an agent that requires approval per signature (Secretive, 1Password) so a background script cannot use loaded keys.",
    "aws-static": "Replace static keys with IAM Identity Center (aws sso login) or aws-vault, then delete the key in IAM.",
    "aws-session": "Already short-lived. Shorten the session duration if you can, and avoid caching admin roles.",
    "cloud": "Switch to short-lived, browser-brokered login and revoke the stored long-lived credential.",
    "kube": "Use an exec credential plugin (cloud CLI or OIDC) instead of an embedded token or client key.",
    "docker": "Set credsStore to osxkeychain and remove inline auth entries. Note any process can still ask the helper.",
    "file-token": "Revoke and reissue this token with the narrowest scope and an expiry; inject it per command (op run, or a Keychain lookup) instead of leaving it on disk.",
    "env": "Do not export secrets in your shell session. Inject them only into the one command that needs them (op run -- cmd).",
    "rc": "Remove the literal from your shell startup file and rotate it. Fetch it at call time from a password manager.",
    "history": "Rotate anything listed, then purge the entries. In zsh set HIST_IGNORE_SPACE and prefix sensitive commands with a space.",
    "dotenv": "Replace values with password-manager references (op run with .env templates) or a per-project secrets tool, and rotate what was exposed.",
    "ai": "Move keys out of the config: reference an environment variable injected at launch, or use the tool's OAuth login. Rotate the key.",
    "keychain": "Tighten the item's access list so only the owning app can read it (Keychain Access > item > Access Control), or move it to a manager that asks per use.",
    "gpg": "Confirm the key has a passphrase and a short gpg-agent cache time, or move it to a hardware key.",
}


def add(layer, kind, title, location, klass, secrets=(), count=None, lifetime="static",
        gate="silent", detail="", confidence="high", fix="file-token", fps=None, path=None):
    fps = sorted(set(fps if fps is not None else [fp(s) for s in secrets]))
    n = count if count is not None else max(len(fps), 1)
    mult = (0.4 if lifetime == "session" else 1.0) * (0.1 if gate == "gated" else 1.0)
    score = round(BASE[klass] * mult * (1 + min(n - 1, 4) * 0.25), 1)
    loc = tilde(location)
    fid = hashlib.sha256("|".join([kind, loc] + fps).encode()).hexdigest()[:12]
    notes = []
    if path is not None:
        d = age_days(path)
        if d is not None and d > 180 and lifetime == "static":
            notes.append("unchanged for %d days" % d)
        if others_can_read(path):
            notes.append("readable by other local users")
    FINDINGS.append(dict(id=fid, layer=layer, kind=kind, title=title, location=loc, klass=klass,
                         count=n, lifetime=lifetime, gate=gate, detail=detail, notes=notes,
                         confidence=confidence, fix=FIX[fix], fingerprints=fps, score=score))


def guarded(name, fn, *a):
    try:
        fn(*a)
    except Exception as e:  # a broken collector must not sink the run
        ERRORS.append("%s: %s" % (name, type(e).__name__))


# --------------------------------------------------------------------------
# layer 1: known credential locations
# --------------------------------------------------------------------------

# kind, title, relative paths, class, capture regex (None = presence only), fix key
SPECS = [
    ("npm-token", "npm auth token", [".npmrc"], "propagation",
     r"(?im)^\s*(?://[^\s=]+:)?(?:_authToken|_auth|_password)\s*=\s*\"?([^\s\"]+)", "npm"),
    ("pypi-token", "PyPI upload credential", [".pypirc"], "propagation",
     r"(?im)^\s*password\s*[=:]\s*(\S+)", "registry"),
    ("cargo-token", "crates.io token", [".cargo/credentials.toml", ".cargo/credentials"], "propagation",
     r"(?im)^\s*token\s*=\s*\"([^\"]+)\"", "registry"),
    ("gem-token", "RubyGems API key", [".gem/credentials"], "propagation",
     r"(?im)^\s*:\w+:\s*(\S+)", "registry"),
    ("gh-token", "GitHub CLI token in plaintext", [".config/gh/hosts.yml"], "propagation",
     r"(?im)^\s*oauth_token:\s*(\S+)", "github"),
    ("git-credentials", "Git credential store (plaintext)", [".git-credentials"], "propagation",
     r"(?m)^https?://[^:\s/]+:([^@\s]+)@", "github"),
    ("netrc", "netrc passwords", [".netrc"], "service", r"(?i)password\s+(\S+)", "file-token"),
    ("gcloud-adc", "Google Cloud application default credentials",
     [".config/gcloud/application_default_credentials.json"], "cloud",
     r"\"(?:refresh_token|private_key)\"\s*:\s*\"([^\"]+)\"", "cloud"),
    ("gcloud-db", "Google Cloud CLI credential database",
     [".config/gcloud/credentials.db", ".config/gcloud/access_tokens.db"], "cloud", None, "cloud"),
    ("azure-cache", "Azure CLI token cache",
     [".azure/msal_token_cache.json", ".azure/accessTokens.json", ".azure/service_principal_entries.json"],
     "cloud", None, "cloud"),
    ("kube", "Kubernetes embedded credentials", [".kube/config"], "cloud",
     r"(?m)^\s*(?:token|client-key-data|password):\s*(\S+)", "kube"),
    ("docker-auth", "Docker registry auth stored inline", [".docker/config.json"], "service",
     r"\"auth\"\s*:\s*\"([^\"]+)\"", "docker"),
    ("terraform", "Terraform Cloud token", [".terraform.d/credentials.tfrc.json", ".terraformrc"], "cloud",
     r"\"?token\"?\s*[:=]\s*\"([^\"]+)\"", "cloud"),
    ("vault", "Vault token", [".vault-token"], "cloud", r"(?s)^\s*(\S+)", "cloud"),
    ("pulumi", "Pulumi access token", [".pulumi/credentials.json"], "cloud", None, "cloud"),
    ("doctl", "DigitalOcean CLI token",
     ["Library/Application Support/doctl/config.yaml", ".config/doctl/config.yaml"], "cloud",
     r"(?im)^\s*access-token:\s*(\S+)", "cloud"),
    ("fly", "Fly.io token", [".fly/config.yml"], "cloud", r"(?im)^\s*access_token:\s*(\S+)", "cloud"),
    ("vercel", "Vercel CLI token",
     ["Library/Application Support/com.vercel.cli/auth.json", ".local/share/com.vercel.cli/auth.json"],
     "cloud", r"\"token\"\s*:\s*\"([^\"]+)\"", "cloud"),
    ("netlify", "Netlify CLI token",
     ["Library/Preferences/netlify/config.json", ".config/netlify/config.json"], "cloud",
     r"\"token\"\s*:\s*\"([^\"]+)\"", "cloud"),
    ("wrangler", "Cloudflare Wrangler token",
     ["Library/Preferences/.wrangler/config/default.toml", ".wrangler/config/default.toml",
      ".config/.wrangler/config/default.toml"], "cloud",
     r"(?im)^\s*(?:oauth_token|refresh_token|api_token)\s*=\s*\"([^\"]+)\"", "cloud"),
    ("firebase", "Firebase CLI refresh token", [".config/configstore/firebase-tools.json"], "cloud",
     r"\"refresh_token\"\s*:\s*\"([^\"]+)\"", "cloud"),
    ("stripe", "Stripe CLI key", [".config/stripe/config.toml"], "service",
     r"(?im)^\s*\w*(?:secret_key|api_key)\w*\s*=\s*['\"]([^'\"]+)", "file-token"),
    ("pgpass", "PostgreSQL password file", [".pgpass"], "service", r"(?m)^[^#\n]*:([^:\n]+)$", "file-token"),
    ("mycnf", "MySQL client password", [".my.cnf"], "service", r"(?im)^\s*password\s*=\s*(\S+)", "file-token"),
    ("rclone", "rclone remote credentials", [".config/rclone/rclone.conf"], "cloud",
     r"(?im)^\s*(?:token|pass|password|secret_access_key|key)\s*=\s*(\S.*)$", "cloud"),
    ("databricks", "Databricks token", [".databrickscfg"], "cloud", r"(?im)^\s*token\s*=\s*(\S+)", "cloud"),
    ("s3cfg", "S3 tool static keys", [".s3cfg", ".boto"], "cloud",
     r"(?im)^\s*(?:secret_key|aws_secret_access_key)\s*=\s*(\S+)", "aws-static"),
    ("age-key", "age / sops private key", [".config/sops/age/keys.txt"], "cloud",
     r"(AGE-SECRET-KEY-[A-Z0-9]+)", "file-token"),
    ("maven", "Maven repository password", [".m2/settings.xml"], "service",
     r"<password>([^<]+)</password>", "file-token"),
    ("gradle", "Gradle properties secrets", [".gradle/gradle.properties"], "service",
     r"(?im)^\s*\S*(?:password|token|secret|key)\S*\s*=\s*(\S+)", "file-token"),
    ("composer", "Composer auth file", [".composer/auth.json", ".config/composer/auth.json"], "service",
     r"\"(?:token|password|[a-z.]+\.(?:com|org|io))\"\s*:\s*\"([^\"]{8,})\"", "file-token"),
]


def collect_known_files():
    for kind, title, rels, klass, rx, fix in SPECS:
        for rel in rels:
            p = HOME / rel
            if not p.is_file():
                continue
            if rx is None:
                if os.access(p, os.R_OK) and p.stat().st_size > 0:
                    st = p.stat()
                    add("files", kind, title, p, klass, fps=[fp("%s|%d|%d" % (rel, st.st_size, int(st.st_mtime)))],
                        fix=fix, path=p, detail="Credential store present and readable (contents not parsed).",
                        confidence="medium")
                continue
            text = read_text(p)
            if text is None:
                continue
            vals = [v.strip() for v in re.findall(rx, text) if looks_real(v.strip())]
            if vals:
                add("files", kind, title, p, klass, secrets=vals, fix=fix, path=p)


def collect_aws():
    for rel in (".aws/credentials", ".aws/config"):
        p = HOME / rel
        text = read_text(p) if p.is_file() else None
        if not text:
            continue
        static, session = [], []
        for sec in re.split(r"(?m)^\s*\[", text):
            m = re.search(r"(?im)^\s*aws_secret_access_key\s*=\s*(\S+)", sec)
            if not m:
                continue
            (session if re.search(r"(?im)^\s*aws_session_token\s*=", sec) else static).append(m.group(1))
        if static:
            add("files", "aws-static", "AWS long-lived access keys", p, "cloud", secrets=static,
                fix="aws-static", path=p)
        if session:
            add("files", "aws-session", "AWS temporary session credentials", p, "cloud", secrets=session,
                lifetime="session", fix="aws-session", path=p)
    live = []
    for d in (".aws/sso/cache", ".aws/cli/cache"):
        base = HOME / d
        if not base.is_dir():
            continue
        for f in base.glob("*.json"):
            try:
                data = json.loads(read_text(f) or "{}")
            except ValueError:
                continue
            tok = data.get("accessToken") or (data.get("Credentials") or {}).get("SecretAccessKey")
            exp = data.get("expiresAt") or (data.get("Credentials") or {}).get("Expiration")
            if not tok:
                continue
            try:
                when = datetime.datetime.fromisoformat(str(exp).replace("Z", "+00:00").replace("UTC", "+00:00"))
                if when.tzinfo is None:
                    when = when.replace(tzinfo=datetime.timezone.utc)
                if when.timestamp() < NOW:
                    continue
            except ValueError:
                pass
            live.append(tok)
    if live:
        add("files", "aws-session", "AWS cached session tokens (unexpired)", HOME / ".aws", "cloud",
            secrets=live, lifetime="session", fix="aws-session")


def ssh_key_encrypted(text):
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        body = "".join(l for l in text.splitlines() if l and not l.startswith("-----"))
        try:
            raw = base64.b64decode(body + "=" * (-len(body) % 4))
        except ValueError:
            return None
        magic = b"openssh-key-v1\x00"
        if not raw.startswith(magic):
            return None
        n = int.from_bytes(raw[len(magic):len(magic) + 4], "big")
        cipher = raw[len(magic) + 4:len(magic) + 4 + n]
        return cipher != b"none"
    return "ENCRYPTED" in text


def collect_ssh():
    d = HOME / ".ssh"
    if d.is_dir():
        for p in sorted(d.iterdir()):
            if not p.is_file() or p.suffix == ".pub" or p.stat().st_size > 20000:
                continue
            text = read_text(p)
            if not text or "PRIVATE KEY-----" not in text:
                continue
            enc = ssh_key_encrypted(text)
            if enc:
                add("files", "ssh-key-encrypted", "SSH private key (passphrase protected)", p, "propagation",
                    secrets=[text], gate="gated", fix="ssh-agent", path=p,
                    detail="File is stealable but needs the passphrase. See the agent finding for live use.")
            else:
                add("files", "ssh-key-plain", "SSH private key with no passphrase", p, "propagation",
                    secrets=[text], fix="ssh-plain", path=p,
                    confidence="high" if enc is False else "medium")
    sock = os.environ.get("SSH_AUTH_SOCK", "")
    if sock:
        rc, out = run(["ssh-add", "-l"], timeout=5)
        keys = [l.split()[1] for l in out.splitlines() if len(l.split()) >= 2 and l.split()[1].startswith(("SHA256:", "MD5:"))]
        if rc == 0 and keys:
            approving = re.search(r"1password|secretive|yubikey", sock, re.I)
            add("ambient", "ssh-agent", "Keys usable through the SSH agent", "$SSH_AUTH_SOCK", "propagation",
                fps=[fp(k) for k in keys], gate="gated" if approving else "silent", fix="ssh-agent",
                confidence="medium" if approving else "high",
                detail=("Agent appears to require approval per use; verify its settings."
                        if approving else
                        "Any process can ask the agent to sign with these keys. Nothing needs to be read from disk."))


# --------------------------------------------------------------------------
# layer 2: ambient state
# --------------------------------------------------------------------------

ENV_SKIP = re.compile(r"(_PATH|_FILE|_SOCK|_DIR|_HOME|_URL|_HELPER|_TYPE)$|^(SSH_AUTH_SOCK|GPG_TTY|XAUTHORITY)$", re.I)


def collect_env():
    groups = {}
    for name, val in os.environ.items():
        if ENV_SKIP.search(name):
            continue
        k = None
        for tk, rx in TOKEN_RX:
            if rx.search(val):
                k = tk
                break
        if k is None and SECRET_NAME_RX.search(name) and looks_real(val) and not val.startswith(("/", "~")):
            k = klass_for_name(name)
        if k:
            groups.setdefault(k, []).append((name, val))
    session = "AWS_SESSION_TOKEN" in os.environ
    for k, items in groups.items():
        names = ", ".join(sorted(n for n, _ in items))
        add("ambient", "env", "Secrets exported in this shell's environment", "environment: " + names, k,
            secrets=[v for _, v in items], fix="env",
            lifetime="session" if (session and all(n.startswith("AWS_") for n, _ in items)) else "static",
            detail="Every child process, including install scripts, inherits these.")


RC_FILES = [".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile",
            ".config/fish/config.fish", ".envrc", ".env"]
HIST_FILES = [".zsh_history", ".bash_history", ".local/share/fish/fish_history", ".python_history",
              ".psql_history", ".mysql_history", ".node_repl_history", ".irb_history"]


def scan_text_file(p, layer, kind, title, fix, detail=""):
    text = read_text(p, limit=8_000_000)
    if not text:
        return
    found = extract_generic(text)
    if found:
        k = max(found.values(), key=lambda c: RANK[c])
        add(layer, kind, title, p, k, secrets=list(found), fix=fix, path=p, detail=detail,
            confidence="medium")


def collect_shell_files():
    for rel in RC_FILES:
        p = HOME / rel
        if p.is_file():
            scan_text_file(p, "ambient", "rc-literal", "Secrets hardcoded in a shell startup file", "rc")
    for rel in HIST_FILES:
        p = HOME / rel
        if p.is_file():
            scan_text_file(p, "ambient", "history", "Secrets left in command history", "history",
                           "Pasted tokens and inline passwords persist here indefinitely.")


SKIP_DIRS = {"Library", "node_modules", ".git", ".Trash", "Pictures", "Music", "Movies", "Applications",
             ".cache", ".npm", ".cargo", ".rustup", ".pyenv", ".nvm", "venv", ".venv", "__pycache__",
             "vendor", "Pods", "DerivedData", ".gradle", ".m2", "dist", "build", ".next", "target",
             ".exposure-audit", ".docker", ".local", "go"}
DOTENV_RX = re.compile(r"^\.env(\.[\w.\-]+)?$")
DOTENV_SAFE = re.compile(r"(example|sample|template|dist|defaults?)$", re.I)


def collect_dotenv(roots, max_depth, skip_protected, budget=25.0):
    deadline = time.time() + budget
    protected = {HOME / "Desktop", HOME / "Documents", HOME / "Downloads"}
    seen = 0
    for root in roots:
        root = Path(root).expanduser()
        base_depth = len(root.parts)
        for cur, dirs, files in os.walk(root, onerror=lambda e: None):
            if time.time() > deadline:
                ERRORS.append("dotenv sweep: time budget reached, results are partial")
                return
            curp = Path(cur)
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS
                       and not (skip_protected and curp / d in protected)
                       and len(curp.parts) - base_depth < max_depth]
            for fn in files:
                p = curp / fn
                if curp == HOME and fn in (".env", ".npmrc"):
                    continue  # handled by the home-level collectors
                if DOTENV_RX.match(fn) and not DOTENV_SAFE.search(fn):
                    seen += 1
                    scan_text_file(p, "ambient", "dotenv", "Project .env file with secrets", "dotenv")
                elif fn == ".npmrc":
                    text = read_text(p) or ""
                    vals = [v for v in re.findall(SPECS[0][4], text) if looks_real(v)]
                    if vals:
                        add("ambient", "npm-token", "npm auth token in a project .npmrc", p, "propagation",
                            secrets=vals, fix="npm", path=p)


# --------------------------------------------------------------------------
# layer 3: keychain items readable without a prompt (metadata + ACL only)
# --------------------------------------------------------------------------

def parse_keychain_dump(text):
    items, cur, entry = [], None, None
    for line in text.splitlines():
        if line.startswith("keychain: "):
            cur = {"class": None, "attrs": {}, "entries": []}
            items.append(cur)
            entry = None
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r'class: "?(\w+)"?', s)
        if m and not cur["entries"] and cur["class"] is None:
            cur["class"] = m.group(1)
            continue
        m = re.match(r'"(\w{4})"<\w+>=(?:0x[0-9A-Fa-f]+\s+)?"(.*)"$', s)
        if m:
            cur["attrs"][m.group(1)] = m.group(2)
            continue
        m = re.match(r'0x00000007 <\w+>=(?:0x[0-9A-Fa-f]+\s+)?"(.*)"$', s)
        if m:
            cur["attrs"]["labl"] = m.group(1)
            continue
        if re.match(r"entry \d+:", s):
            entry = {"auth": [], "apps": None, "any": False}
            cur["entries"].append(entry)
            continue
        if entry is None:
            continue
        if s.startswith("authorizations"):
            entry["auth"] = s.split(":", 1)[1].split() if ":" in s else []
        elif s.startswith("applications: <null>"):
            entry["any"] = True
        elif s.startswith("applications ("):
            entry["apps"] = []
        else:
            m = re.match(r"\d+: (.+?)(?: \((?:OK|status:? ?-?\d+)\))?$", s)
            if m and entry["apps"] is not None:
                entry["apps"].append(m.group(1))
    return items


def classify_keychain_item(item):
    """Returns ('any'|'tools'|'apps'|'unknown', [tool paths])."""
    dec = [e for e in item["entries"] if "decrypt" in e["auth"]]
    if not dec:
        return "unknown", []
    if any(e["any"] for e in dec):
        return "any", []
    apps = [a for e in dec for a in (e["apps"] or [])]
    tools = [a for a in apps if a.startswith("/") and ".app/" not in a and not a.endswith(".app")]
    return ("tools", tools) if tools else ("apps", [])


KC_STATS = {}


def collect_keychain():
    if not IS_MAC:
        return
    kc = HOME / "Library/Keychains/login.keychain-db"
    if not kc.exists():
        return
    rc, out = run(["security", "dump-keychain", "-a", str(kc)], timeout=45)
    if rc != 0 or not out:
        ERRORS.append("keychain: could not list items (timed out or denied)")
        return
    items = [i for i in parse_keychain_dump(out) if i["class"] in ("genp", "inet")]
    KC_STATS.update(total=len(items), silent=0, app_gated=0, unknown=0)
    for it in items:
        how, tools = classify_keychain_item(it)
        a = it["attrs"]
        svc = a.get("svce") or a.get("srvr") or a.get("labl") or "(unnamed)"
        acct = a.get("acct", "")
        if how == "apps":
            KC_STATS["app_gated"] += 1
            continue
        if how == "unknown":
            KC_STATS["unknown"] += 1
            continue
        KC_STATS["silent"] += 1
        name = svc + " " + acct
        klass = ("propagation" if re.search(r"github|gh:|gitlab|npm|pypi", name, re.I)
                 else "cloud" if CLOUD_NAME_RX.search(name) else "service")
        via = "any application" if how == "any" else ", ".join(sorted(set(tools)))
        add("keychain", "keychain-silent", "Keychain item readable without a prompt",
            "login keychain: %s%s" % (svc, " (%s)" % acct if acct else ""), klass,
            fps=[fp("kc|%s|%s" % (svc, acct))], fix="keychain", confidence="medium",
            detail="Access list trusts %s, so a script can read it by calling that tool. "
                   "Value was not read by this audit." % via)


# --------------------------------------------------------------------------
# layer 4: AI tooling configs
# --------------------------------------------------------------------------

AI_FILES = [
    ".claude.json", ".claude/settings.json", ".claude/.credentials.json",
    "Library/Application Support/Claude/claude_desktop_config.json",
    ".cursor/mcp.json", ".codeium/windsurf/mcp_config.json",
    ".codex/auth.json", ".codex/config.toml",
    ".gemini/settings.json", ".gemini/oauth_creds.json",
    ".config/github-copilot/hosts.json", ".config/github-copilot/apps.json",
    ".continue/config.json", ".continue/config.yaml", ".aider.conf.yml",
    ".config/goose/config.yaml", ".config/zed/settings.json",
    "Library/Application Support/Code/User/mcp.json",
    "Library/Application Support/Code/User/settings.json",
    "Library/Application Support/Cursor/User/settings.json",
]


def collect_ai():
    for rel in AI_FILES:
        p = HOME / rel
        if p.is_file():
            scan_text_file(p, "ai", "ai-config", "API keys in an AI tool or MCP config", "ai",
                           "MCP server entries often embed long-lived keys in env blocks.")


# --------------------------------------------------------------------------
# layer 6: context and data reach
# --------------------------------------------------------------------------

CONTEXT = {}
REACH = []

# label, relative path, protection ("tcc" may prompt, "fda" silently denied without Full Disk
# Access, "open" has no OS protection), note
REACH_TARGETS = [
    ("Desktop", "Desktop", "tcc", ""),
    ("Documents", "Documents", "tcc", ""),
    ("Downloads", "Downloads", "tcc", ""),
    ("iCloud Drive", "Library/Mobile Documents", "tcc", ""),
    ("Cloud storage (Dropbox, Drive, OneDrive)", "Library/CloudStorage", "tcc", ""),
    ("Photos library", "Pictures/Photos Library.photoslibrary", "tcc", ""),
    ("Contacts", "Library/Application Support/AddressBook", "tcc", ""),
    ("Calendars", "Library/Calendars", "tcc", ""),
    ("Notes", "Library/Group Containers/group.com.apple.notes", "tcc", ""),
    ("Mail", "Library/Mail", "fda", ""),
    ("Messages", "Library/Messages", "fda", ""),
    ("Safari data", "Library/Safari", "fda", ""),
    ("Chrome profile", "Library/Application Support/Google/Chrome", "open",
     "History and bookmarks are plaintext; cookie values are encrypted with an app-gated Keychain key."),
    ("Firefox profiles", "Library/Application Support/Firefox/Profiles", "open",
     "Session cookies are stored in plaintext; saved logins are decryptable unless a primary password is set."),
    ("Arc profile", "Library/Application Support/Arc", "open", "Same model as Chrome."),
    ("Brave profile", "Library/Application Support/BraveSoftware/Brave-Browser", "open", "Same model as Chrome."),
    ("Edge profile", "Library/Application Support/Microsoft Edge", "open", "Same model as Chrome."),
    ("Slack data", "Library/Application Support/Slack", "open", "Local cache and workspace metadata."),
    ("Signal data", "Library/Application Support/Signal", "open", "Database is encrypted; key is Keychain-gated on current versions."),
]


def measure(path, budget=3.0):
    deadline = time.time() + budget
    total = files = 0
    partial = False
    stack = [str(path)]
    while stack:
        if time.time() > deadline:
            partial = True
            break
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            files += 1
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return total, files, partial


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def collect_context(probe_folders):
    CONTEXT["user"] = os.environ.get("USER", "")
    CONTEXT["os"] = ("macOS " + platform.mac_ver()[0]) if IS_MAC else platform.platform()
    CONTEXT["terminal"] = os.environ.get("TERM_PROGRAM", "unknown")
    chain, pid = [], os.getppid()
    for _ in range(8):
        rc, out = run(["ps", "-o", "ppid=,comm=", "-p", str(pid)], timeout=3)
        parts = out.strip().split(None, 1)
        if rc != 0 or len(parts) < 2:
            break
        chain.append(os.path.basename(parts[1]))
        pid = int(parts[0])
        if pid <= 1:
            break
    CONTEXT["launched_by"] = " < ".join(chain) or "unknown"
    fda = None
    if IS_MAC:
        try:
            with open(HOME / "Library/Application Support/com.apple.TCC/TCC.db", "rb") as f:
                f.read(1)
            fda = True
        except PermissionError:
            fda = False
        except OSError:
            fda = None
    CONTEXT["full_disk_access"] = fda
    CONTEXT["folder_probe"] = probe_folders
    for label, rel, prot, note in REACH_TARGETS:
        p = HOME / rel
        if not os.path.lexists(p):
            continue
        if prot == "tcc" and not probe_folders and not fda:
            REACH.append(dict(label=label, path=tilde(p), status="not probed", size="", files="", note=note))
            continue
        try:
            with os.scandir(p) as it:
                next(it, None)
            ok = True
        except OSError:
            ok = False
        if not ok:
            REACH.append(dict(label=label, path=tilde(p), status="blocked", size="", files="", note=note))
            continue
        size, files, partial = measure(p)
        pre = "at least " if partial else ""
        REACH.append(dict(label=label, path=tilde(p), status="readable", size=pre + human(size),
                          files=pre + "{:,}".format(files), note=note))


# --------------------------------------------------------------------------
# history and diff
# --------------------------------------------------------------------------

def save_and_diff(snapshot):
    hist = STATE / "history"
    hist.mkdir(mode=0o700, exist_ok=True)
    prev = None
    olds = sorted(hist.glob("*.json"))
    if olds:
        try:
            prev = json.loads(olds[-1].read_text())
        except (OSError, ValueError):
            prev = None
    out = hist / (datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + ".json")
    fd = os.open(out, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(snapshot, f, indent=1)
    if not prev:
        return None
    old = {f["id"]: f for f in prev.get("findings", [])}
    new = {f["id"]: f for f in snapshot["findings"]}
    return dict(previous_time=prev.get("time", ""), previous_score=prev.get("score", 0),
                delta=round(snapshot["score"] - prev.get("score", 0), 1),
                added=[new[i] for i in new if i not in old],
                resolved=[old[i] for i in old if i not in new])


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

CSS = """
:root{--bg:#fbfaf7;--card:#fff;--ink:#1c1b19;--mute:#6b6862;--line:#e4e1d9;--hot:#b3261e;--warm:#b06000;
--cool:#1f6f5c;--chip:#f1eee7}
@media(prefers-color-scheme:dark){:root{--bg:#161513;--card:#1f1e1b;--ink:#ece9e2;--mute:#a09c93;
--line:#34322d;--hot:#ff8a80;--warm:#f2b24c;--cool:#6fd0b5;--chip:#2a2925}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
main{max-width:920px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}h2{font-size:16px;margin:36px 0 12px}
.sub{color:var(--mute);font-size:13px}
.hero{display:flex;gap:24px;align-items:flex-end;flex-wrap:wrap;margin:24px 0 8px}
.score{font-size:64px;font-weight:650;line-height:1;font-variant-numeric:tabular-nums;letter-spacing:-.03em}
.delta{font-size:14px;font-weight:600}.up{color:var(--hot)}.down{color:var(--cool)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:16px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:22px;font-variant-numeric:tabular-nums}.tile span{color:var(--mute);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.card h3{margin:0;font-size:15px}.loc{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--mute);
word-break:break-all;margin:3px 0 8px}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}
.chip{background:var(--chip);border-radius:99px;padding:2px 9px;font-size:11.5px;white-space:nowrap}
.chip.hot{color:var(--hot)}.chip.warm{color:var(--warm)}.chip.cool{color:var(--cool)}
.fix{border-top:1px solid var(--line);margin-top:10px;padding-top:9px;font-size:13.5px}
.fix b{font-weight:600}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mute);font-weight:500;font-size:12px}td.n{font-variant-numeric:tabular-nums;white-space:nowrap}
.mono{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
details{margin-top:8px}summary{cursor:pointer;color:var(--mute);font-size:13px}
ul{padding-left:18px;margin:6px 0}li{margin:3px 0}
"""


def e(s):
    return html.escape(str(s))


def chips(f):
    c = ['<span class="chip %s">%s</span>' % ("hot" if f["klass"] == "propagation" else "warm" if f["klass"] == "cloud" else "", e(KLASS_LABEL[f["klass"]]))]
    c.append('<span class="chip %s">%s</span>' % (("cool", "needs approval") if f["gate"] == "gated" else ("hot", "silent")))
    c.append('<span class="chip">%s</span>' % ("short-lived" if f["lifetime"] == "session" else "long-lived"))
    if f["count"] > 1:
        c.append('<span class="chip">%d secrets</span>' % f["count"])
    if f["confidence"] != "high":
        c.append('<span class="chip">%s confidence</span>' % e(f["confidence"]))
    for n in f["notes"]:
        c.append('<span class="chip warm">%s</span>' % e(n))
    return '<div class="chips">%s</div>' % "".join(c)


def render(snapshot, diff, dupes):
    fs = snapshot["findings"]
    ctx = snapshot["context"]
    by = {k: sum(1 for f in fs if f["klass"] == k and f["gate"] == "silent") for k in BASE}
    h = ['<!doctype html><html lang="en"><head><meta charset="utf-8">'
         '<meta name="viewport" content="width=device-width,initial-scale=1">'
         '<title>Exposure Audit</title><style>%s</style></head><body><main>' % CSS]
    h.append('<h1>Exposure audit</h1><div class="sub">%s &middot; launched by %s &middot; %s</div>'
             % (e(snapshot["time"]), e(ctx["launched_by"]), e(ctx["os"])))
    d = ""
    if diff:
        cls = "up" if diff["delta"] > 0 else "down"
        d = '<div class="delta %s">%+.1f since %s</div>' % (cls, diff["delta"], e(diff["previous_time"]))
    h.append('<div class="hero"><div><div class="sub">Exposure score (lower is better)</div>'
             '<div class="score">%s</div>%s</div></div>' % (e(snapshot["score"]), d))
    fda = ctx["full_disk_access"]
    h.append('<div class="tiles">')
    for k in ("propagation", "cloud", "service", "generic"):
        h.append('<div class="tile"><b>%d</b><span>%s, silent</span></div>' % (by[k], e(KLASS_LABEL[k])))
    h.append('<div class="tile"><b>%s</b><span>Full Disk Access inherited</span></div>'
             % ("Yes" if fda else "No" if fda is False else "n/a"))
    h.append("</div>")

    if diff and (diff["added"] or diff["resolved"]):
        h.append("<h2>Changes since last run</h2><div class='card'>")
        if diff["resolved"]:
            h.append("<b>Resolved</b><ul>%s</ul>" % "".join(
                "<li>%s <span class='mono'>%s</span></li>" % (e(f["title"]), e(f["location"])) for f in diff["resolved"]))
        if diff["added"]:
            h.append("<b>New</b><ul>%s</ul>" % "".join(
                "<li>%s <span class='mono'>%s</span></li>" % (e(f["title"]), e(f["location"])) for f in diff["added"]))
        h.append("</div>")

    top = fs[:12]
    h.append("<h2>Fix these first</h2>")
    if not top:
        h.append('<div class="card">Nothing found. Run it from the terminal you actually install packages from to be sure.</div>')
    for i, f in enumerate(top, 1):
        h.append('<div class="card"><h3>%d. %s</h3><div class="loc">%s</div>%s' % (i, e(f["title"]), e(f["location"]), chips(f)))
        if f["detail"]:
            h.append("<div>%s</div>" % e(f["detail"]))
        dd = [o for x in f["fingerprints"] for o in dupes.get(x, []) if o != f["location"]]
        if dd:
            h.append('<div class="sub">Same secret also found at: %s</div>' % e(", ".join(sorted(set(dd)))))
        h.append('<div class="fix"><b>Fix:</b> %s</div></div>' % e(f["fix"]))

    h.append("<h2>Data reach</h2><div class='sub'>What the same process can read beyond credentials. Not included in the score.</div>")
    h.append('<div class="card tw"><table><tr><th>Location</th><th>Status</th><th>Size</th><th>Files</th><th>Note</th></tr>')
    for r in snapshot["reach"]:
        col = "hot" if r["status"] == "readable" else "cool" if r["status"] == "blocked" else ""
        h.append('<tr><td>%s<div class="mono">%s</div></td><td><span class="chip %s">%s</span></td>'
                 '<td class="n">%s</td><td class="n">%s</td><td>%s</td></tr>'
                 % (e(r["label"]), e(r["path"]), col, e(r["status"]), e(r["size"]), e(r["files"]), e(r["note"])))
    h.append("</table></div>")

    kc = snapshot.get("keychain") or {}
    if kc:
        h.append("<h2>Login keychain</h2><div class='card'>%d password items: <b>%d readable without a prompt</b>, "
                 "%d gated to specific apps, %d undetermined.</div>"
                 % (kc["total"], kc["silent"], kc["app_gated"], kc["unknown"]))

    h.append("<h2>All findings (%d)</h2><div class='card tw'><table><tr><th>Score</th><th>Finding</th>"
             "<th>Location</th><th>Access</th><th>Fingerprints</th></tr>" % len(fs))
    for f in fs:
        h.append('<tr><td class="n">%s</td><td>%s</td><td class="mono">%s</td><td>%s, %s</td><td class="mono">%s</td></tr>'
                 % (e(f["score"]), e(f["title"]), e(f["location"]), e(f["gate"]),
                    "short-lived" if f["lifetime"] == "session" else "long-lived",
                    e(" ".join(f["fingerprints"][:4]) + (" ..." if len(f["fingerprints"]) > 4 else ""))))
    h.append("</table></div>")

    h.append("<h2>How to read this</h2><div class='card'><ul>"
             "<li>This reflects the terminal it was launched from. Rerun it from every terminal and IDE you install packages in; their permissions differ.</li>"
             "<li>Score per finding = class weight (worm vector 10, cloud 8, service 5, unclassified 3), reduced 60% if short-lived and 90% if it needs your approval.</li>"
             "<li>Offline only: it cannot tell whether a token is still valid or what it is scoped to.</li>"
             "<li>Fingerprints are salted with a key that stays on this machine. They let you spot the same secret in several places and track it across runs.</li>"
             "<li>Keychain results come from access lists, not from reading items, and do not model partition lists, so treat them as likely rather than certain.</li>"
             "<li>This report maps where your secrets live. Keep it local.</li></ul>")
    if snapshot["errors"]:
        h.append("<details><summary>Collector notes (%d)</summary><ul>%s</ul></details>"
                 % (len(snapshot["errors"]), "".join("<li>%s</li>" % e(x) for x in snapshot["errors"])))
    h.append("</div></main></body></html>")
    return "".join(h)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    global SALT
    ap = argparse.ArgumentParser(description="Audit what an install script could silently read or use.")
    ap.add_argument("--no-folder-probe", action="store_true",
                    help="skip Desktop/Documents/Downloads/iCloud probes (they can trigger a macOS consent prompt)")
    ap.add_argument("--skip-keychain", action="store_true", help="skip the login keychain access-list check")
    ap.add_argument("--roots", nargs="*", default=[str(HOME)], help="directories to sweep for .env files")
    ap.add_argument("--max-depth", type=int, default=5, help="depth limit for the .env sweep")
    ap.add_argument("--json", action="store_true", help="print the snapshot as JSON instead of a summary")
    ap.add_argument("--open", action="store_true", help="open the HTML report when done")
    args = ap.parse_args()

    SALT = load_salt()
    probe = not args.no_folder_probe
    if IS_MAC and probe:
        sys.stderr.write("Note: if macOS asks whether your terminal may access a folder, that prompt is itself the "
                         "result (not silently readable). Answer however you normally would.\n")

    guarded("context", collect_context, probe)
    guarded("known files", collect_known_files)
    guarded("aws", collect_aws)
    guarded("ssh", collect_ssh)
    guarded("environment", collect_env)
    guarded("shell files", collect_shell_files)
    blocked = not probe and not CONTEXT.get("full_disk_access")
    guarded("dotenv sweep", collect_dotenv, args.roots, args.max_depth, blocked)
    if not args.skip_keychain:
        guarded("keychain", collect_keychain)
    guarded("ai configs", collect_ai)

    FINDINGS.sort(key=lambda f: (-f["score"], f["location"]))
    dupes = {}
    for f in FINDINGS:
        for x in f["fingerprints"]:
            dupes.setdefault(x, []).append(f["location"])
    dupes = {k: v for k, v in dupes.items() if len(set(v)) > 1}

    snapshot = dict(version=VERSION, time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                    score=round(sum(f["score"] for f in FINDINGS), 1), context=CONTEXT, reach=REACH,
                    keychain=KC_STATS, findings=FINDINGS, errors=ERRORS)
    diff = save_and_diff(snapshot)
    report = STATE / "report.html"
    fd = os.open(report, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(render(snapshot, diff, dupes))

    if args.json:
        print(json.dumps(snapshot, indent=1))
    else:
        silent = [f for f in FINDINGS if f["gate"] == "silent"]
        print("\nExposure score: %s%s" % (snapshot["score"], ("  (%+.1f since last run)" % diff["delta"]) if diff else ""))
        print("Findings: %d total, %d silently usable, %d worm vectors"
              % (len(FINDINGS), len(silent), sum(1 for f in silent if f["klass"] == "propagation")))
        fda = CONTEXT.get("full_disk_access")
        print("Launched by: %s | Full Disk Access inherited: %s"
              % (CONTEXT.get("launched_by"), "YES" if fda else "no" if fda is False else "n/a"))
        if FINDINGS:
            print("\nFix first:")
            for i, f in enumerate(FINDINGS[:5], 1):
                print("  %d. [%5.1f] %s\n             %s" % (i, f["score"], f["title"], f["location"]))
        if ERRORS:
            print("\nCollector notes: " + "; ".join(ERRORS))
        print("\nReport: %s" % report)
    if args.open and IS_MAC:
        run(["open", str(report)])


if __name__ == "__main__":
    main()

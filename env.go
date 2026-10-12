package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"
)

// Env is everything a collector may learn about the machine. Collectors never
// call os.Getenv, os.UserHomeDir, exec.Command or time.Now directly, so tests
// can hand them a temp home, a fake environment and a stub Run.
type Env struct {
	Home    string
	Root    string            // filesystem root for the few paths outside the home; "/" except in tests
	Environ map[string]Secret // values are secrets too; a map[string]string leaks under t.Logf("%+v", env) (A-10)
	GOOS    string
	Now     time.Time
	PID     int // start of the ps parent chain for the context key
	Run     func(ctx context.Context, c Cmd) (stdout []byte, exit int, err error)

	salt Secret // a Secret so formatting an Env never prints it
}

// Fingerprint is the salted fingerprint of a secret value.
func (e *Env) Fingerprint(s Secret) string { return s.Fingerprint(e.salt.bytes()) }

// FingerprintLabel fingerprints a non-secret label, such as kind|relative
// path for a credential store whose contents are not parsed.
func (e *Env) FingerprintLabel(label string) string {
	return fingerprint(e.salt.bytes(), []byte(label))
}

// Cmd is one subprocess invocation. Stdin is always closed (A-08).
type Cmd struct {
	Path string   // one of AllowedPrograms (invariant 8)
	Args []string // not including the program name
	Env  []string // full replacement environment
}

// The only environment variables readable as plain text. A test asserts this list is exactly these five. (A-33)
var PlainEnv = []string{"__CFBundleIdentifier", "TERM_PROGRAM", "SSH_AUTH_SOCK", "TMUX", "USER"}

// Plain returns the value of a variable on PlainEnv, and "" for any other name.
func (e *Env) Plain(name string) string {
	if !slices.Contains(PlainEnv, name) {
		return ""
	}
	return string(e.Environ[name].bytes())
}

// AllowedPrograms is invariant 8: absolute paths, never through a shell or PATH.
var AllowedPrograms = []string{"/usr/bin/security", "/usr/bin/ssh-add", "/bin/ps", "/usr/bin/open"}

var errProgramNotAllowed = errors.New("program not allowed")

// guardRun refuses any program outside AllowedPrograms before calling run.
func guardRun(run func(context.Context, Cmd) ([]byte, int, error)) func(context.Context, Cmd) ([]byte, int, error) {
	return func(ctx context.Context, c Cmd) ([]byte, int, error) {
		if !slices.Contains(AllowedPrograms, c.Path) {
			return nil, -1, errProgramNotAllowed
		}
		return run(ctx, c)
	}
}

func execRun(ctx context.Context, c Cmd) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.Env = c.Env
	if cmd.Env == nil {
		cmd.Env = []string{} // nil would inherit ours, secrets included
	}
	// Stdin left nil reads from the null device: closed for our purposes.
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.Bytes(), exit.ExitCode(), nil
	}
	if err != nil {
		return nil, -1, err
	}
	return out.Bytes(), 0, nil
}

// RealEnv is the only place that touches the process environment.
func RealEnv() (*Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	environ := map[string]Secret{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			environ[k] = NewSecret([]byte(v))
		}
	}
	return &Env{
		Home:    home,
		Root:    "/",
		Environ: environ,
		GOOS:    runtime.GOOS,
		Now:     time.Now(),
		PID:     os.Getpid(),
		Run:     guardRun(execRun),
	}, nil
}

package main

import (
	"strings"
	"testing"
)

// corpusCase is one line of text. want is the secret that must be found in
// it; "" on a true positive means any match counts, and every false
// positive must yield nothing.
type corpusCase struct {
	text, want string
}

// hexN and uuidLike build fixture values at runtime (HANDOFF §4).
func hexN(n int) string {
	return strings.Map(func(r rune) rune { return rune("0123456789abcdef"[int(r)%16]) }, randomAlnum(n))
}

func uuidLike() string {
	h := hexN(32)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// knownFormatCases is the number of leading true positives that a token
// format catches; the rest are matched by name only.
const knownFormatCases = 9

func truePositives() []corpusCase {
	r := randomAlnum
	ghp, npm := "gh"+"p_"+r(36), "np"+"m_"+r(36)
	cases := []corpusCase{
		{"export GITHUB_TOKEN=" + ghp, ghp},
		{"//registry.npmjs.org/:_authToken=" + npm, npm},
		{"https://x-access-token:" + ghp + "@github.com/o/r.git", ghp},
		{"SLACK_BOT_TOKEN=xo" + "xb-" + r(12) + "-" + r(24), ""},
		{"ANTHROPIC_API_KEY=sk-" + "ant-" + r(40), ""},
		{"OPENAI_API_KEY=sk-" + "proj-" + r(48), ""},
		{"STRIPE_KEY=sk_" + "live_" + r(24), ""},
		{"HF_TOKEN=h" + "f_" + r(34), ""},
		{"GOOGLE_API_KEY=AI" + "za" + r(35), ""},
	}
	for _, c := range []struct{ pre, val, post string }{
		{"_auth=", r(24) + "==", ""},
		{"DB_PASSWORD=", r(24), ""},
		{"MY_SERVICE_TOKEN=", r(32), ""},
		{`"apiKey": "`, r(32), `"`},
		{"client_secret: ", r(40), ""},
		{"AWS_SECRET_ACCESS_KEY=", r(18) + "/" + r(10) + "+" + r(11), ""},
		{"password = ", r(20), ""},
		{"DATABASE_URL=postgres://app:", r(24), "@db/app"},
		{"CLAUDE_CODE_MESSAGING_TOKEN=", r(32), ""},
		{"SENTRY_AUTH_TOKEN=", hexN(64), ""},
		{"HEROKU_API_KEY=", uuidLike(), ""},
		{"npmAuthToken: ", r(36), ""},
		{`"privateKey": "`, r(44), `"`},
		{"PGPASSWORD=", r(20), ""},
		{"accessToken: ", r(20) + "." + r(30) + "." + r(22), ""},
		{"DB_PASSWORD=", "Tr0ub4dor&3xK9!", ""},
	} {
		cases = append(cases, corpusCase{c.pre + c.val + c.post, c.val})
	}
	return cases
}

func falsePositives() []corpusCase {
	lines := []string{
		"author = Jane Example <jane@example.com>",
		`"author": "someone-longname"`,
		"AUTH=required_always",
		`"auth": "oauth-provider"`,
		"API_KEY=your_key_here",
		"TOKEN=changeme123",
		"PASSWORD=<password goes here>",
		"SECRET=${SECRET_FROM_VAULT}",
		"TOKEN_EXPIRY=3600seconds",
		"PASSWORD_MIN_LENGTH=12345678",
		"OAUTH_CALLBACK_URL=https://example.com/cb",
		"AUTH_PROVIDER=github-oauth",
		"tokenizer: wordpiece-v2-large",
		"passwordless_login=enabled-now",
		"auth_flow: authorization_code",
		"TOKEN_FILE=/run/secrets/token",
		"SECRET_SOURCE=production",
		"AUTHORITY=login.microsoftonline.com",
		"DATABASE_URL=postgres://postgres:postgres@localhost:5432/app",
		"SECRET_NAME=prod-db-secret",
		"AUTH_TOKEN=xxxxxxxxxxxxxxxx",
		"my_token_count=123456789",
		"api_key_header: X-Api-Key-Value",
		"token_type: bearer_access",
		"export GIT_ASKPASS_TOKEN_HELPER=/usr/local/bin/helper",
		"client_credentials_grant: client_credentials",
		// Dummy development values: not word-shaped, so only the entropy floor stops them.
		"SECRET=abc123abc123",
		"TOKEN=test1234test1234",
		"password: hunter2hunter2",
		"API_TOKEN=aaaaabbbbb12345",
	}
	cases := make([]corpusCase, len(lines))
	for i, l := range lines {
		cases[i] = corpusCase{text: l}
	}
	return cases
}

func found(env *Env, c corpusCase, ms []Match) bool {
	if c.want == "" {
		return len(ms) > 0
	}
	fp := env.Fingerprint(NewSecret([]byte(c.want)))
	for _, m := range ms {
		if env.Fingerprint(m.Value) == fp {
			return true
		}
	}
	return false
}

// TestMatcherCorpus prints both rates (M3). Run with -v to see them.
func TestMatcherCorpus(t *testing.T) {
	env := newFixture(t).env()
	tps, fps := truePositives(), falsePositives()
	if len(tps) < 20 || len(fps) < 20 {
		t.Fatalf("corpus has %d true and %d false positives; want at least 20 each", len(tps), len(fps))
	}
	hitTP, hitFP := 0, 0
	for i, c := range tps {
		if found(env, c, extractSecrets([]byte(c.text))) {
			hitTP++
		} else {
			// Index only: the line holds a fixture secret.
			t.Errorf("true positive %d missed", i)
		}
	}
	for _, c := range fps {
		if len(extractSecrets([]byte(c.text))) > 0 {
			hitFP++
			t.Errorf("false positive: %q", c.text)
		}
	}
	t.Logf("true positive rate %d/%d = %.0f%%; false positive rate %d/%d = %.0f%%",
		hitTP, len(tps), 100*float64(hitTP)/float64(len(tps)), hitFP, len(fps), 100*float64(hitFP)/float64(len(fps)))
}

// TestEntropyFloorRates prints how the value checks fare at floors around
// the chosen one, as evidence for entropyFloor. False positives here are
// only those whose names pass isSecretName, so the value checks alone decide.
func TestEntropyFloorRates(t *testing.T) {
	var tpVals, fpVals [][]byte
	for _, c := range truePositives()[knownFormatCases:] {
		tpVals = append(tpVals, []byte(c.want))
	}
	for _, c := range falsePositives() {
		if sm := kvRx.FindSubmatch([]byte(c.text)); sm != nil && isSecretName(string(sm[1])) {
			fpVals = append(fpVals, sm[2])
		}
	}
	for _, floor := range []float64{2.5, 3.0, 3.5, 4.0} {
		tp, fp, fpNoShape := 0, 0, 0
		for _, v := range tpVals {
			if plausibleAt(v, floor) {
				tp++
			}
		}
		for _, v := range fpVals {
			if plausibleAt(v, floor) {
				fp++
			}
			if looksReal(v) && !hasAnyPrefix(v, "/", "~", "http://", "https://") && entropy(v) >= floor {
				fpNoShape++
			}
		}
		t.Logf("floor %.1f: name-only true positives kept %d/%d; false positives kept %d/%d (%d without the word-shape rule)",
			floor, tp, len(tpVals), fp, len(fpVals), fpNoShape)
		if floor == entropyFloor && (tp != len(tpVals) || fp != 0) {
			t.Errorf("at the chosen floor: %d/%d kept, %d false positives", tp, len(tpVals), fp)
		}
	}
}

// Fixture values matched only by name are random alphanumerics; they must
// clear the floor every time (A-18).
func TestFixtureValuesClearEntropyFloor(t *testing.T) {
	for _, n := range []int{20, 24, 32} {
		for range 2000 {
			v := randomAlnum(n)
			if !plausibleByName([]byte(v)) {
				t.Fatalf("random %d-character value rejected (entropy %.2f)", n, entropy([]byte(v)))
			}
		}
	}
}

func TestIsSecretName(t *testing.T) {
	for name, want := range map[string]bool{
		"AUTH_TOKEN": true, "_auth": true, "_authToken": true, "npmAuthToken": true, "apiKey": true,
		"APIKey": true, "api-key": true, "x-api-key": true, "db_password": true, "PGPASSWORD": true,
		"client_secret": true, "AWS_SECRET_ACCESS_KEY": true, "privateKey": true, "credentials": true,
		"HIGH_WATER_TOKEN": true,
		"author":           false, "AUTHORITY": false, "OAUTH_CALLBACK": false, "oauth": false, "tokenizer": false,
		"passwordless": false, "TOKEN_EXPIRY": false, "PASSWORD_MIN_LENGTH": false, "AUTH_PROVIDER": false,
		"SECRET_NAME": false, "TOKEN_FILE": false, "SSH_AUTH_SOCK": false, "STRIPE_KEY": false, "token_type": false,
	} {
		if got := isSecretName(name); got != want {
			t.Errorf("isSecretName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestNameWords(t *testing.T) {
	for in, want := range map[string]string{
		"npmAuthToken": "npm auth token", "APIKey": "api key", "_authToken": "auth token",
		"AWS_SECRET_ACCESS_KEY": "aws secret access key", "x-api-key": "x api key", "OAuth2Token": "o auth2 token",
	} {
		if got := strings.Join(nameWords(in), " "); got != want {
			t.Errorf("nameWords(%q) = %q, want %q", in, got, want)
		}
	}
}

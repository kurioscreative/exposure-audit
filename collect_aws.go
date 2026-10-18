package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	awsSectionRx = regexp.MustCompile(`(?m)^\s*\[`)
	awsSecretRx  = regexp.MustCompile(`(?im)^\s*aws_secret_access_key\s*=\s*(\S+)`)
	awsSessionRx = regexp.MustCompile(`(?im)^\s*aws_session_token\s*=`)
)

// ssoRefreshFix is for SSO caches holding a refresh token (decision 13).
const ssoRefreshFix = "This cache holds an IAM Identity Center refresh token that mints new credentials for weeks. Run `aws sso logout` when you finish, and shorten the session duration in IAM Identity Center."

type awsCollector struct{}

func (awsCollector) Name() string { return "aws" }

func (awsCollector) Collect(ctx context.Context, env *Env) ([]Finding, error) {
	var out []Finding
	for _, rel := range []string{".aws/credentials", ".aws/config"} {
		out = append(out, awsProfiles(env, filepath.Join(env.Home, rel))...)
	}
	if ctx.Err() != nil {
		return out, ErrPartial
	}
	out = append(out, awsCaches(env)...)
	return out, nil
}

// awsProfiles splits a credentials file into long-lived and session keys.
// Each key pair is one credential, fingerprinted by its secret access key.
func awsProfiles(env *Env, p string) []Finding {
	text, err := env.readFile(p, defaultReadLimit)
	if err != nil {
		return nil
	}
	var static, session []Match
	for _, sec := range awsSectionRx.Split(string(text), -1) {
		m := awsSecretRx.FindStringSubmatch(sec)
		if m == nil {
			continue
		}
		match := Match{Value: NewSecret([]byte(m[1])), Class: Cloud, Name: "aws_secret_access_key"}
		if awsSessionRx.MatchString(sec) {
			session = append(session, match)
		} else {
			static = append(static, match)
		}
	}
	var out []Finding
	loc := env.tilde(p)
	if len(static) > 0 {
		out = append(out, Finding{
			Layer: "files", Kind: "aws-static", Title: "AWS long-lived access keys", Location: loc,
			Fix: fixText["aws-static"], Hits: env.hits(static), Notes: env.fileNotes(p, Static),
		})
	}
	if len(session) > 0 {
		out = append(out, Finding{
			Layer: "files", Kind: "aws-session", Title: "AWS temporary session credentials", Location: loc,
			Lifetime: Session, Fix: fixText["aws-session"], Hits: env.hits(session), Notes: env.fileNotes(p, Session),
		})
	}
	return out
}

type awsCache struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt"`
	Credentials  struct {
		SecretAccessKey string `json:"SecretAccessKey"`
		Expiration      string `json:"Expiration"`
	} `json:"Credentials"`
}

// awsCaches reads the SSO and CLI caches. A cache with a refreshToken is a
// static credential whether or not its access token has expired, because
// the refresh token mints new ones (decision 13, A-16). Medium confidence:
// refresh-token lifetime depends on the IAM Identity Center session setting,
// unverified on a developer Mac. Other caches count only while unexpired.
func awsCaches(env *Env) []Finding {
	var refresh, live []Match
	for _, d := range []string{".aws/sso/cache", ".aws/cli/cache"} {
		paths, _ := filepath.Glob(filepath.Join(env.Home, d, "*.json")) // sorted
		for _, p := range paths {
			b, err := env.readFile(p, defaultReadLimit)
			if err != nil {
				continue
			}
			var c awsCache
			if json.Unmarshal(b, &c) != nil {
				continue
			}
			if c.RefreshToken != "" {
				refresh = append(refresh, Match{Value: NewSecret([]byte(c.RefreshToken)), Class: Cloud, Name: "refreshToken"})
				continue
			}
			tok, exp := c.AccessToken, c.ExpiresAt
			if tok == "" {
				tok, exp = c.Credentials.SecretAccessKey, c.Credentials.Expiration
			}
			if tok == "" || awsExpired(exp, env.Now) {
				continue
			}
			live = append(live, Match{Value: NewSecret([]byte(tok)), Class: Cloud})
		}
	}
	var out []Finding
	if len(refresh) > 0 {
		out = append(out, Finding{
			Layer: "files", Kind: "aws-sso-refresh", Title: "AWS SSO cache with a refresh token",
			Location: env.tilde(filepath.Join(env.Home, ".aws/sso/cache")), Confidence: Medium,
			Detail: "The refresh token mints new credentials until the SSO session ends, even after the access token expires.",
			Fix:    ssoRefreshFix, Hits: env.hits(refresh),
		})
	}
	if len(live) > 0 {
		out = append(out, Finding{
			Layer: "files", Kind: "aws-session", Title: "AWS cached session tokens (unexpired)",
			Location: env.tilde(filepath.Join(env.Home, ".aws")), Lifetime: Session,
			Fix: fixText["aws-session"], Hits: env.hits(live),
		})
	}
	return out
}

// awsExpired follows the prototype: an unparseable expiry counts as live.
func awsExpired(s string, now time.Time) bool {
	s = strings.Replace(s, "UTC", "Z", 1)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Before(now)
		}
	}
	return false
}

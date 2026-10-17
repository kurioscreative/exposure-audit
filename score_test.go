package main

import (
	"fmt"
	"slices"
	"testing"
)

func fnd(kind, loc string, cls Class, fps ...string) Finding {
	f := Finding{Kind: kind, Title: kind, Location: loc, Fix: "fix " + kind}
	for _, fp := range fps {
		f.Hits = append(f.Hits, Hit{Fingerprint: fp, Class: cls})
	}
	return f
}

func with(f Finding, mod func(*Finding)) Finding {
	mod(&f)
	f.finalize()
	return f
}

func fin(f Finding) Finding { f.finalize(); return f }

func TestHitWeightMultipliers(t *testing.T) {
	cases := []struct {
		class     Class
		life      Lifetime
		gate      Gate
		committed bool
		want      float64
	}{
		{Propagation, Static, Silent, false, 10},
		{Cloud, Static, Silent, false, 8},
		{Agent, Static, Silent, false, 5},
		{Service, Static, Silent, false, 5},
		{Generic, Static, Silent, false, 3},
		{Cloud, Session, Silent, false, 3.2},
		{Propagation, Static, Windowed, false, 5},
		{Propagation, Static, Gated, false, 1},
		{Service, Static, Silent, true, 2.5},
		{Cloud, Session, Windowed, true, 0.8},
	}
	for _, c := range cases {
		f := Finding{Lifetime: c.life, Gate: c.gate, Committed: c.committed}
		if got := hitWeight(&f, Hit{Class: c.class}); round1(got) != c.want {
			t.Errorf("%v/%v/%v/committed=%v: %v, want %v", c.class, c.life, c.gate, c.committed, got, c.want)
		}
	}
}

func TestRoundHalfToEven(t *testing.T) {
	// 6.25 is exact in binary; math.Round would give 6.3 (A-03).
	for in, want := range map[float64]float64{6.25: 6.2, 6.35: 6.4, 3.2: 3.2, 0.05: 0} {
		if got := round1(in); got != want {
			t.Errorf("round1(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestTiers(t *testing.T) {
	cases := []struct {
		class Class
		gate  Gate
		want  int
	}{
		{Propagation, Silent, 1}, {Propagation, Windowed, 1}, {Cloud, Silent, 2}, {Cloud, Windowed, 2},
		{Agent, Silent, 3}, {Service, Windowed, 3}, {Generic, Silent, 4}, {Generic, Windowed, 4},
		{Propagation, Gated, 5}, {Generic, Gated, 5},
	}
	for _, c := range cases {
		fs := []Finding{with(fnd("k", "~/x", c.class, "fp1"), func(f *Finding) { f.Gate = c.gate })}
		creds, items, _ := score(fs)
		if creds[0].Tier != c.want || items[0].Tier != c.want {
			t.Errorf("%v %v: credential tier %d, item tier %d, want %d", c.class, c.gate, creds[0].Tier, items[0].Tier, c.want)
		}
	}
}

func TestSameFingerprintInTwoFilesIsOneCredential(t *testing.T) {
	fs := []Finding{
		fin(fnd("gh-token", "~/.config/gh/hosts.yml", Propagation, "ghp")),
		with(fnd("history", "~/.zsh_history", Generic, "ghp"), func(f *Finding) { f.Confidence = Medium }),
	}
	creds, items, total := score(fs)
	if len(creds) != 1 || total != 10 {
		t.Fatalf("got %d credentials, total %v; want 1, 10", len(creds), total)
	}
	if creds[0].Class != Propagation {
		t.Errorf("class %v, want the highest across hits", creds[0].Class)
	}
	if len(items) != 1 || len(items[0].Locations) != 2 {
		t.Errorf("want one item with two locations, got %+v", items)
	}
	if items[0].Title != "gh-token" {
		t.Errorf("title %q, want the highest-scoring finding's (A-39)", items[0].Title)
	}
}

func TestCredentialScoreIsHighestAcrossLocations(t *testing.T) {
	// The same SSH key: gated in the file, silent through the agent (A-15).
	fs := []Finding{
		with(fnd("ssh-key-encrypted", "~/.ssh/id_enc", Propagation, "key"), func(f *Finding) { f.Gate = Gated }),
		fin(fnd("ssh-agent", "ssh agent", Propagation, "key")),
	}
	creds, items, total := score(fs)
	if total != 10 || creds[0].Tier != 1 || items[0].Tier != 1 {
		t.Errorf("total %v tier %d; want 10, tier 1", total, creds[0].Tier)
	}
}

func TestSameSetOfLocationsIsOneItem(t *testing.T) {
	env := fnd("dotenv", "~/code/app/.env", Generic, "db")
	env.Hits = append(env.Hits, Hit{Fingerprint: "stripe", Class: Service})
	wt := fnd("dotenv", "~/code/app-wt/.env", Generic, "db")
	wt.Hits = append(wt.Hits, Hit{Fingerprint: "stripe", Class: Service})
	_, items, total := score([]Finding{fin(env), fin(wt)})
	if len(items) != 1 || items[0].Score != 8 || total != 8 || len(items[0].Credentials) != 2 {
		t.Errorf("items %+v total %v; want one item scoring 8", items, total)
	}
}

func TestDifferentKindsInOneFileAreSeparateItems(t *testing.T) {
	static := fnd("aws-static", "~/.aws/credentials", Cloud, "ak")
	session := with(fnd("aws-session", "~/.aws/credentials", Cloud, "st"), func(f *Finding) { f.Lifetime = Session })
	_, items, _ := score([]Finding{fin(static), session})
	if len(items) != 2 || items[0].Score != 8 || items[1].Score != 3.2 {
		t.Errorf("items %+v; want 8.0 then 3.2", items)
	}
}

// The §11 base fixture expressed as findings: checks totals and order
// independently of the collectors.
func TestBaseFixtureScoring(t *testing.T) {
	envf := fnd("dotenv", "~/code/app/.env", Generic, "db")
	envf.Hits = append(envf.Hits, Hit{Fingerprint: "stripe", Class: Service})
	fs := []Finding{
		fin(fnd("npm-token", "~/.npmrc", Propagation, "npm")),
		fin(fnd("aws-static", "~/.aws/credentials", Cloud, "ak")),
		with(fnd("aws-session", "~/.aws/credentials", Cloud, "st"), func(f *Finding) { f.Lifetime = Session }),
		fin(fnd("gh-token", "~/.config/gh/hosts.yml", Propagation, "ghp")),
		fin(fnd("history", "~/.zsh_history", Propagation, "ghp")),
		fin(fnd("rc-literal", "~/.zshrc", Service, "skproj")),
		fin(envf),
		fin(fnd("ai-config", "~/.cursor/mcp.json", Propagation, "pat")),
		fin(fnd("ssh-key-plain", "~/.ssh/id_plain", Propagation, "plain")),
		with(fnd("ssh-key-encrypted", "~/.ssh/id_enc", Propagation, "enc"), func(f *Finding) { f.Gate = Gated }),
		fin(fnd("env", "environment", Generic, "mysvc")),
	}
	creds, items, total := score(fs)
	if total != 68.2 || len(creds) != 11 {
		t.Fatalf("total %v with %d credentials; want 68.2 with 11", total, len(creds))
	}
	var got []string
	for _, it := range items {
		got = append(got, it.Locations[0])
	}
	want := []string{
		"~/.config/gh/hosts.yml", "~/.cursor/mcp.json", "~/.npmrc", "~/.ssh/id_plain", // tier 1, 10.0, by location
		"~/.aws/credentials", "~/.aws/credentials", // tier 2: 8.0 then 3.2
		"~/code/app/.env", "~/.zshrc", // tier 3: 8.0 then 5.0
		"environment",   // tier 4
		"~/.ssh/id_enc", // tier 5
	}
	if !slices.Equal(got, want) {
		t.Errorf("order\n got %v\nwant %v", got, want)
	}
}

func TestRankingTierBeatsScore(t *testing.T) {
	envf := fnd("dotenv", "~/code/app/.env", Cloud, "a1", "a2", "a3", "a4")
	_, items, _ := score([]Finding{fin(envf), fin(fnd("npm-token", "~/.npmrc", Propagation, "npm"))})
	if items[0].Locations[0] != "~/.npmrc" || items[1].Score != 32 {
		t.Errorf("items %+v; want npm (tier 1) above the 32.0 .env (R-01)", items)
	}
}

// An item's findings, and the finding its title comes from, follow path
// order: IDs hash fingerprints, so ID order changed whenever a secret rotated (A-64).
func TestItemFindingsInPathOrder(t *testing.T) {
	for i := range 30 {
		fp := fmt.Sprintf("ak%d", i) // each fingerprint stands for one rotation
		b := fin(fnd("b-kind", "~/.aws/credentials", Cloud, fp))
		a := fin(fnd("a-kind", "~/.aws/credentials", Cloud, fp))
		z := fin(fnd("history", "~/.zsh_history", Cloud, fp))
		_, items, _ := score([]Finding{z, b, a})
		it := items[0]
		if want := []string{a.ID, b.ID, z.ID}; !slices.Equal(it.Findings, want) {
			t.Fatalf("fingerprint %s: findings %v, want %v", fp, it.Findings, want)
		}
		if it.Title != "a-kind" || it.Fix != "fix a-kind" {
			t.Fatalf("fingerprint %s: title %q fix %q, want the first tied finding in path order", fp, it.Title, it.Fix)
		}
	}
}

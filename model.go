package main

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"
)

type Class string

const (
	Propagation Class = "propagation" // npm, GitHub, registries, SSH: makes the victim a worm vector
	Cloud       Class = "cloud"
	Agent       Class = "agent" // coding-agent session tokens (decision 11)
	Service     Class = "service"
	Generic     Class = "generic"
)

type Gate string

const (
	Silent   Gate = "silent"
	Windowed Gate = "windowed" // an approval is cached for a while (decision 10)
	Gated    Gate = "gated"    // passphrase, touch or approval each time
)

type Lifetime string

const (
	Static  Lifetime = "static"
	Session Lifetime = "session"
)

type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Hit is one secret at a finding's location. Name is a variable or key name
// if known, never the value.
type Hit struct {
	Fingerprint string `json:"fingerprint"`
	Class       Class  `json:"class"`
	Name        string `json:"name,omitempty"`
}

// Finding is one location where credentials were found.
type Finding struct {
	ID         string     `json:"id"`
	SlotID     string     `json:"slot_id"`
	Layer      string     `json:"layer"`
	Kind       string     `json:"kind"`
	Title      string     `json:"title"`
	Location   string     `json:"location"`
	Lifetime   Lifetime   `json:"lifetime"`
	Gate       Gate       `json:"gate"`
	Committed  bool       `json:"committed,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Notes      []string   `json:"notes,omitempty"`
	Confidence Confidence `json:"confidence"`
	Fix        string     `json:"fix"`
	Hits       []Hit      `json:"hits"`
	Collector  string     `json:"collector"`

	// Live-only text for findings whose persisted Title or Location must not
	// name Keychain services or accounts (decision 16). Never serialized.
	LiveTitle    string `json:"-"`
	LiveLocation string `json:"-"`
}

func (f *Finding) DisplayTitle() string {
	if f.LiveTitle != "" {
		return f.LiveTitle
	}
	return f.Title
}

func (f *Finding) DisplayLocation() string {
	if f.LiveLocation != "" {
		return f.LiveLocation
	}
	return f.Location
}

// finalize fills SlotID (unless a collector set it, as the Keychain does) and ID.
func (f *Finding) finalize() {
	if f.SlotID == "" {
		f.SlotID = shortHash(f.Kind, f.Location)
	}
	fps := make([]string, 0, len(f.Hits))
	for _, h := range f.Hits {
		fps = append(fps, h.Fingerprint)
	}
	slices.Sort(fps)
	f.ID = shortHash(append([]string{f.Kind, f.Location}, fps...)...)
	if f.Lifetime == "" {
		f.Lifetime = Static
	}
	if f.Gate == "" {
		f.Gate = Silent
	}
	if f.Confidence == "" {
		f.Confidence = High
	}
}

// shortHash is sha256(a|b|...)[:12] in hex.
func shortHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:12]
}

const snapshotSchema = 1

// Snapshot is one run, as written to history and printed by -json.
type Snapshot struct {
	Schema     int               `json:"schema"`
	Version    string            `json:"version"`
	Time       time.Time         `json:"time"`
	Collectors map[string]Status `json:"collectors"`
	Errors     []CollectorError  `json:"errors"`
	Findings   []Finding         `json:"findings"`
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

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
	Schema         int               `json:"schema"`
	Version        string            `json:"version"`
	Time           time.Time         `json:"time"`
	Context        Context           `json:"context"`
	FullDiskAccess string            `json:"full_disk_access"` // yes, no or unknown (inferred in M2)
	Total          float64           `json:"total"`
	Collectors     map[string]Status `json:"collectors"`
	Errors         []CollectorError  `json:"errors"`
	Findings       []Finding         `json:"findings"`
	Credentials    []Credential      `json:"credentials"`
	Items          []Item            `json:"items"`
	Reach          []ReachRow        `json:"reach,omitempty"`
	Prevention     []PreventionRow   `json:"prevention,omitempty"`
	Keychain       *KeychainStats    `json:"keychain,omitempty"`
	Diff           *Diff             `json:"diff,omitempty"`
}

// ReachRow is one data-reach target: measured, not scored (decision 1).
type ReachRow struct {
	Label   string `json:"label"`
	Path    string `json:"path"`   // ~/relative
	Status  string `json:"status"` // readable, blocked, not probed
	Bytes   int64  `json:"bytes,omitempty"`
	Files   int    `json:"files,omitempty"`
	Partial bool   `json:"partial,omitempty"` // size budget hit: sizes are lower bounds
	Note    string `json:"note,omitempty"`
}

// PreventionRow is one install-script control (decision 19), unscored.
type PreventionRow struct {
	Tool    string `json:"tool"`    // npm, Yarn, pnpm, Bun
	Setting string `json:"setting"` // e.g. ignore-scripts
	State   string `json:"state"`   // on, off, not configured
	Fix     string `json:"fix,omitempty"`
}

// KeychainStats counts login keychain password items by access class.
type KeychainStats struct {
	Total    int `json:"total"`
	Silent   int `json:"silent"`
	AppGated int `json:"app_gated"`
	Unknown  int `json:"unknown"`
}

// sectioner is implemented by collectors that also report unscored data.
// Section is called only for a complete or partial collector, after Collect
// returned, so the collector's fields are no longer being written.
type sectioner interface {
	Section(s *Snapshot)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

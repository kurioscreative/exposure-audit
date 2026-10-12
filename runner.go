package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Collector finds credentials in one area.
type Collector interface {
	Name() string
	Collect(ctx context.Context, env *Env) ([]Finding, error)
}

type Status string

const (
	Complete Status = "complete"
	Partial  Status = "partial" // a budget was hit; findings are kept but incomplete
	Failed   Status = "failed"
	Timeout  Status = "timeout"
	Skipped  Status = "skipped" // not applicable, or turned off (A-37)
)

// Collectors return these to set a status other than complete or failed.
var (
	ErrPartial = errors.New("partial")
	ErrSkipped = errors.New("skipped")
)

// CollectorError holds only fixed strings. err.Error() is never stored:
// some standard library errors quote their input, which could be a secret.
type CollectorError struct {
	Collector string `json:"collector"`
	Category  string `json:"category"` // "error", "panic", "timeout", "output-leak"
}

type runResult struct {
	Findings []Finding
	Statuses map[string]Status
	Errors   []CollectorError
}

type collectorState struct {
	wg       sync.WaitGroup
	mu       sync.Mutex
	panicked bool
}

type stateKey struct{}

// Go starts fn in a goroutine whose panic is contained and charged to the
// calling collector. Collectors must use it instead of a bare go statement:
// recover only works in its own goroutine (A-11). The runner waits for these
// goroutines before accepting the collector's result.
func Go(ctx context.Context, fn func()) {
	st := ctx.Value(stateKey{}).(*collectorState)
	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		defer func() {
			if recover() != nil {
				st.mu.Lock()
				st.panicked = true
				st.mu.Unlock()
			}
		}()
		fn()
	}()
}

type collected struct {
	name     string
	findings []Finding
	status   Status
	category string
}

// runCollectors runs every collector concurrently under one deadline (A-12).
// A collector that ignores ctx is abandoned at the deadline and reported as a
// timeout; its goroutine may linger until the process exits.
func runCollectors(cs []Collector, env *Env, deadline time.Duration) runResult {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	// Buffered so abandoned collectors never block on send.
	done := make(chan collected, len(cs))
	for _, c := range cs {
		go runOne(ctx, c, env, done)
	}

	res := runResult{Statuses: map[string]Status{}}
	for range cs {
		select {
		case r := <-done:
			res.Statuses[r.name] = r.status
			res.Findings = append(res.Findings, r.findings...)
			if r.category != "" {
				res.Errors = append(res.Errors, CollectorError{r.name, r.category})
			}
		case <-ctx.Done():
			for _, c := range cs {
				if _, ok := res.Statuses[c.Name()]; !ok {
					res.Statuses[c.Name()] = Timeout
					res.Errors = append(res.Errors, CollectorError{c.Name(), "timeout"})
				}
			}
			return res
		}
	}
	return res
}

func runOne(ctx context.Context, c Collector, env *Env, done chan<- collected) {
	name := c.Name()
	st := &collectorState{}
	ctx = context.WithValue(ctx, stateKey{}, st)
	r := collected{name: name}
	defer func() {
		if recover() != nil {
			r = collected{name: name, status: Failed, category: "panic"}
		}
		done <- r
	}()

	findings, err := c.Collect(ctx, env)
	st.wg.Wait()
	st.mu.Lock()
	panicked := st.panicked
	st.mu.Unlock()

	switch {
	case panicked:
		r.status, r.category = Failed, "panic"
		return
	case err == nil:
		r.status = Complete
	case errors.Is(err, ErrSkipped):
		r.status = Skipped
		return
	case errors.Is(err, ErrPartial):
		r.status = Partial
	case errors.Is(err, context.DeadlineExceeded):
		r.status, r.category = Timeout, "timeout"
		return
	default:
		r.status, r.category = Failed, "error"
		return
	}
	for i := range findings {
		findings[i].Collector = name
		findings[i].finalize()
	}
	r.findings = findings
}

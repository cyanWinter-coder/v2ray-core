package dns

import (
	"fmt"
	"strings"
	"time"

	"github.com/v2fly/v2ray-core/v5/common/net"
)

const lookupHistoryLimit = 64

// LookupAttempt describes one name server query attempted for a domain.
type LookupAttempt struct {
	Server   string
	Duration time.Duration
	Fallback bool
	Error    error
}

// LookupTrace describes a complete DNS lookup, including every attempted
// server, the selected server, elapsed time and the final error.
type LookupTrace struct {
	Domain         string
	Started        time.Time
	Duration       time.Duration
	Attempts       []LookupAttempt
	SelectedServer string
	IPs            []net.IP
	Err            error
}

// LookupError is returned when every name server, including configured
// fallback servers, fails. It deliberately contains all attempts so callers
// and logs can see the fallback order and per-server latency.
type LookupError struct {
	Domain    string
	Attempts  []LookupAttempt
	LastError error
}

func (e *LookupError) Error() string {
	if e == nil {
		return "dns lookup failed"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "dns lookup failed for domain %s: all %d name server(s) failed", e.Domain, len(e.Attempts))
	for _, attempt := range e.Attempts {
		serverType := "primary"
		if attempt.Fallback {
			serverType = "fallback"
		}
		errText := "<empty response>"
		if attempt.Error != nil {
			errText = attempt.Error.Error()
		}
		fmt.Fprintf(&builder, "; %s server %s after %s: %s", serverType, attempt.Server, attempt.Duration, errText)
	}
	return builder.String()
}

// Unwrap exposes the last server error to errors.Is/errors.As.
func (e *LookupError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.LastError
}

// Inner implements common/errors.hasInnerError for errors.Cause.
func (e *LookupError) Inner() error {
	return e.Unwrap()
}

func (s *DNS) recordLookupTrace(trace LookupTrace) {
	s.traceMu.Lock()
	if s.lastTraces == nil {
		s.lastTraces = make(map[string]LookupTrace)
	}
	trace.Attempts = append([]LookupAttempt(nil), trace.Attempts...)
	trace.IPs = append([]net.IP(nil), trace.IPs...)
	s.lastTraces[trace.Domain] = trace
	s.history = append(s.history, trace)
	if len(s.history) > lookupHistoryLimit {
		s.history = append([]LookupTrace(nil), s.history[len(s.history)-lookupHistoryLimit:]...)
	}
	observer := s.observer
	s.traceMu.Unlock()

	if observer != nil {
		observer(trace)
	}
}

// LastLookup returns the most recent lookup trace for a domain.
func (s *DNS) LastLookup(domain string) (LookupTrace, bool) {
	domain = strings.TrimSuffix(domain, ".")
	s.traceMu.RLock()
	defer s.traceMu.RUnlock()
	trace, found := s.lastTraces[domain]
	return trace, found
}

// LookupHistory returns up to the last 64 lookup traces in completion order.
func (s *DNS) LookupHistory() []LookupTrace {
	s.traceMu.RLock()
	defer s.traceMu.RUnlock()
	return append([]LookupTrace(nil), s.history...)
}

// SetLookupObserver registers a callback invoked after every completed lookup.
func (s *DNS) SetLookupObserver(observer func(LookupTrace)) {
	s.traceMu.Lock()
	defer s.traceMu.Unlock()
	s.observer = observer
}

package access

import (
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// maxGroups is Signal's cap on one summary's groups (SignInSummary.groups).
const maxGroups = 1024

// groupKey is what makes sign-ins one group: account, method, certificate and source.
type groupKey struct {
	account, keyID, ca, keyFP, from string
	method                          eventsv1.SignInGroup_Method
}

// Window groups the sign-ins of one report window. Memory is bounded by maxGroups: a
// sign-in that would start group 1,025 is counted in dropped.
type Window struct {
	shared  SharedKeys
	start   time.Time
	groups  map[groupKey]*eventsv1.SignInGroup
	order   []groupKey
	dropped uint64
}

// NewWindow starts a window at start. Plain keys keep their fingerprint only when shared
// lists it.
func NewWindow(start time.Time, shared SharedKeys) *Window {
	return &Window{shared: shared, start: start, groups: map[groupKey]*eventsv1.SignInGroup{}}
}

// Add counts one sign-in. An account Signal would refuse is counted in dropped.
func (w *Window) Add(l Login) {
	if !ValidAccount(l.Account) {
		w.dropped++
		return
	}
	if _, listed := w.shared[l.KeyFingerprint]; !listed {
		l.KeyFingerprint = ""
	}
	k := groupKey{account: l.Account, keyID: l.KeyID, ca: l.CAFingerprint, keyFP: l.KeyFingerprint, from: l.FromIP, method: l.Method}
	g, ok := w.groups[k]
	if !ok {
		if len(w.groups) == maxGroups {
			w.dropped++
			return
		}
		g = &eventsv1.SignInGroup{Account: k.account, Method: k.method, KeyId: k.keyID, CaFingerprint: k.ca,
			KeyFingerprint: k.keyFP, FromIp: k.from, FirstAt: timestamppb.New(l.At), LastAt: timestamppb.New(l.At)}
		w.groups[k] = g
		w.order = append(w.order, k)
	}
	g.Count++
	if l.At.Before(g.GetFirstAt().AsTime()) {
		g.FirstAt = timestamppb.New(l.At)
	}
	if !l.At.Before(g.GetLastAt().AsTime()) {
		g.LastAt = timestamppb.New(l.At)
		if l.Serial != "" {
			g.Serial = l.Serial
		}
	}
}

// Empty reports whether the window holds nothing to say.
func (w *Window) Empty() bool { return len(w.groups) == 0 && w.dropped == 0 }

// Flush returns the window's summary, ending at now (or at its latest sign-in, if that is
// later: a clock that stepped back), and starts the next window where it ends.
func (w *Window) Flush(now time.Time) *eventsv1.SignInSummary {
	start, end := w.start, now
	s := &eventsv1.SignInSummary{Dropped: w.dropped}
	for _, k := range w.order {
		g := w.groups[k]
		start = minTime(start, g.GetFirstAt().AsTime())
		end = maxTime(end, g.GetLastAt().AsTime())
		s.Groups = append(s.Groups, g)
	}
	s.WindowStart, s.WindowEnd = timestamppb.New(start), timestamppb.New(end)
	w.start, w.groups, w.order, w.dropped = end, map[groupKey]*eventsv1.SignInGroup{}, nil, 0
	return s
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// Trust states: what a host lets in over SSH (the scout's cert-only, both and key-only).
// Static keys are known only when AuthorizedKeysFile is none (no keys) or a plain key was
// seen signing in (keys); otherwise the state is a pair of possibilities.
const (
	TrustCertOnly     = "cert-only"
	TrustBoth         = "both"
	TrustKeyOnly      = "key-only"
	TrustNone         = "none"
	TrustCertOrBoth   = "cert-only or both"
	TrustKeyOnlyOrNot = "key-only or none"
	TrustUnknown      = "unknown"
)

// TrustState derives the host's trust state from its access state (does sshd trust a
// signing key, are keys off) and whether a plain key was seen signing in.
func TrustState(a *eventsv1.HostAccess, keySeen bool) string {
	s := a.GetSshd()
	if !s.GetRead() {
		return TrustUnknown
	}
	cert := len(s.GetTrustedUserCaKeys()) > 0
	// A key seen signing in wins over "AuthorizedKeysFile none": an AuthorizedKeysCommand,
	// which this package does not read, can still supply keys.
	switch {
	case keySeen && cert:
		return TrustBoth
	case keySeen:
		return TrustKeyOnly
	case s.GetAuthorizedKeysFile() == "none" && cert:
		return TrustCertOnly
	case s.GetAuthorizedKeysFile() == "none":
		return TrustNone
	case cert:
		return TrustCertOrBoth
	}
	return TrustKeyOnlyOrNot
}

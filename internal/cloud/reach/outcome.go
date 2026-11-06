package reach

// Outcome is a path's verdict, shared by every cloud's judge: closed, undetermined (the
// data cannot decide; the listener keeps its level) or open.
type Outcome int

// The three outcomes.
const (
	Closed Outcome = iota
	Undetermined
	Open
)

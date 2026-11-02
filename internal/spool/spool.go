// Package spool is a size-capped FIFO of unsent messages that survives restarts.
//
// Messages are appended to segment files in a directory and fsynced; a small
// cursor file records how far the sender got. With no directory the spool is
// memory only. If a disk write fails, the message is kept in a memory tail
// behind the on-disk records, so nothing is lost or reordered; the tail drains
// back to disk, oldest first, on the next successful Push.
//
// Order guarantee: Head/Pop deliver all on-disk records (oldest first), then the
// memory tail (oldest first). New messages always go behind everything queued.
//
// Dropped is a lower bound: a bad record ends its segment and counts as one
// drop however many records followed it. In memory (memory-only mode or after a
// write error) at most maxBytes>>10 messages are held, one at least; the oldest
// is dropped beyond that.
//
// A Spool is safe for concurrent use.
package spool

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const cursorFile = "cursor"

// memMsgSize is what each message counts for against maxBytes in the memory tail.
const memMsgSize = 1 << 10

type segment struct {
	index uint64
	size  int64 // bytes of valid records
	n     int   // valid records
}

// Spool is the queue of unsent messages.
type Spool struct {
	mu       sync.Mutex
	dir      string // "" = memory only
	maxBytes int64
	segBytes int64
	ready    chan struct{} // capacity 1; signalled by Push

	segs      []segment // oldest first; the last is the one appended to
	nextIndex uint64
	active    *os.File // append handle for the last segment, nil until needed
	forceNew  bool     // the last segment saw a failed write: start a fresh one
	curOff    int64    // byte offset of the head record in segs[0]
	consumed  int      // records of segs[0] already popped
	disk      int      // unsent records on disk
	head      *Msg     // cached head record of segs[0]
	headLen   int64

	tail         []Msg // messages kept in memory (memory-only mode, or after a write error)
	writeFailing bool  // inside a streak of failed writes (log once per streak)
	cursorFailed bool

	dropped, overflowed uint64
}

// Open opens (creating if needed) the spool in dir and replays unsent records.
// dir == "" keeps everything in memory, where maxBytes counts each message as
// 1 KiB. segmentBytes is the size at which a new segment file is started.
func Open(dir string, maxBytes, segmentBytes int64) (*Spool, error) {
	s := &Spool{dir: dir, maxBytes: maxBytes, segBytes: segmentBytes, ready: make(chan struct{}, 1)}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	if err := s.replay(); err != nil {
		return nil, err
	}
	return s, nil
}

func segName(index uint64) string { return fmt.Sprintf("%016x.seg", index) }

func (s *Spool) segPath(index uint64) string { return filepath.Join(s.dir, segName(index)) }

// replay loads the segment list and cursor, validating every record and
// truncating each segment at its first bad one.
func (s *Spool) replay() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	var indexes []uint64
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".seg") || len(name) != 16+len(".seg") {
			continue
		}
		if idx, err := strconv.ParseUint(name[:16], 16, 64); err == nil {
			indexes = append(indexes, idx)
		}
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })

	curIdx, curOff := s.readCursor()
	for _, idx := range indexes {
		if idx < curIdx { // fully consumed before a crash
			_ = os.Remove(s.segPath(idx))
			continue
		}
		seg, offs, err := s.scanSegment(idx)
		if err != nil {
			return err
		}
		s.segs = append(s.segs, seg)
		if idx == curIdx { // offs[i] is the end offset of record i
			s.curOff = min(curOff, seg.size)
			for s.consumed < seg.n && offs[s.consumed] <= s.curOff {
				s.consumed++
			}
			s.curOff = 0
			if s.consumed > 0 {
				s.curOff = offs[s.consumed-1]
			}
		}
	}
	if len(s.segs) > 0 && s.segs[0].index != curIdx {
		s.curOff, s.consumed = 0, 0
	}
	for i, seg := range s.segs {
		s.disk += seg.n
		if i == 0 {
			s.disk -= s.consumed
		}
	}
	s.nextIndex = curIdx + 1
	if len(s.segs) > 0 {
		s.nextIndex = max(s.nextIndex, s.segs[len(s.segs)-1].index+1)
		// Persist the normalized position: a truncation may have put it below the old cursor.
		s.writeCursor()
	}
	return nil
}

func (s *Spool) readCursor() (idx uint64, off int64) {
	b, err := os.ReadFile(filepath.Join(s.dir, cursorFile))
	if err != nil {
		return 0, 0
	}
	var o uint64
	if _, err := fmt.Sscanf(string(b), "%d %d", &idx, &o); err != nil {
		return 0, 0
	}
	return idx, int64(o)
}

// scanSegment validates the records of one segment and truncates it at the first
// bad one, counting the lost remainder as dropped. It returns the end offset of
// each valid record.
func (s *Spool) scanSegment(idx uint64) (segment, []int64, error) {
	path := s.segPath(idx)
	b, err := os.ReadFile(path)
	if err != nil {
		return segment{}, nil, fmt.Errorf("spool: %w", err)
	}
	seg := segment{index: idx}
	var offs []int64
	pos := 0
	for pos < len(b) {
		_, n, err := decodeRecord(b[pos:])
		if err != nil {
			slog.Warn("spool: bad record, truncating segment", "segment", segName(idx), "offset", pos, "err", err)
			s.dropped++
			if terr := os.Truncate(path, int64(pos)); terr != nil {
				return segment{}, nil, fmt.Errorf("spool: %w", terr)
			}
			break
		}
		pos += n
		offs = append(offs, int64(pos))
		seg.n++
	}
	seg.size = int64(pos)
	return seg, offs, nil
}

// Ready is signalled (without blocking the pusher) when a message is pushed.
func (s *Spool) Ready() <-chan struct{} { return s.ready }

// Push queues m behind everything already queued. It never blocks and never
// fails: a message that cannot be written is kept in memory and the error is
// logged once per streak.
func (s *Spool) Push(m Msg) {
	s.mu.Lock()
	s.push(m)
	s.mu.Unlock()
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

func (s *Spool) push(m Msg) {
	if s.dir == "" {
		s.pushTail(m)
		return
	}
	rec, err := encodeRecord(m)
	if err != nil {
		slog.Error("spool: message cannot be encoded, dropping", "id", m.ID, "err", err)
		s.dropped++
		return
	}
	// Anything in the tail is older than m: move it to disk first, in order.
	for len(s.tail) > 0 {
		old, err := encodeRecord(s.tail[0])
		if err == nil {
			if err = s.appendDisk(old); err != nil {
				s.pushTail(m)
				return
			}
		} else {
			s.dropped++
		}
		s.tail[0] = Msg{}
		s.tail = s.tail[1:]
	}
	if err := s.appendDisk(rec); err != nil {
		s.pushTail(m)
	}
}

// pushTail adds to the memory tail, dropping the oldest at the cap.
func (s *Spool) pushTail(m Msg) {
	if limit := max(int(s.maxBytes/memMsgSize), 1); len(s.tail) >= limit {
		s.tail[0] = Msg{}
		s.tail = s.tail[1:]
		s.dropped++
		s.overflowed++
	}
	s.tail = append(s.tail, m)
}

// appendDisk writes rec to the active segment (rolling and evicting as needed)
// and fsyncs it. On error the segment is left as it was.
func (s *Spool) appendDisk(rec []byte) (err error) {
	defer func() {
		switch {
		case err != nil && !s.writeFailing:
			s.writeFailing = true
			slog.Error("spool: disk write failed, keeping messages in memory", "dir", s.dir, "err", err)
		case err == nil && s.writeFailing:
			s.writeFailing = false
			slog.Info("spool: disk writes recovered", "dir", s.dir)
		}
	}()
	if err = s.openActive(int64(len(rec))); err != nil {
		return err
	}
	s.evictFor(int64(len(rec)))
	last := &s.segs[len(s.segs)-1]
	if _, err = s.active.Write(rec); err == nil {
		err = s.active.Sync()
	}
	if err != nil {
		_ = s.active.Close()
		s.active = nil
		s.forceNew = true
		_ = os.Truncate(s.segPath(last.index), last.size) // best effort: drop a partial record
		return err
	}
	last.size += int64(len(rec))
	last.n++
	s.disk++
	return nil
}

// openActive makes sure there is an open segment with room for a record of r bytes.
func (s *Spool) openActive(r int64) error {
	var last *segment
	if len(s.segs) > 0 {
		last = &s.segs[len(s.segs)-1]
	}
	needNew := last == nil || s.forceNew || (last.size > 0 && last.size+r > s.segBytes)
	if s.active != nil && !needNew {
		return nil
	}
	if s.active != nil {
		_ = s.active.Close()
		s.active = nil
	}
	flags := os.O_WRONLY | os.O_APPEND
	index := s.nextIndex
	if needNew {
		flags |= os.O_CREATE | os.O_EXCL
	} else {
		index = last.index
	}
	f, err := os.OpenFile(s.segPath(index), flags, 0o600)
	if err != nil {
		return err
	}
	s.active = f
	if needNew {
		s.segs = append(s.segs, segment{index: index})
		s.nextIndex = index + 1
		s.forceNew = false
	}
	return nil
}

// evictFor deletes whole oldest segments (never the one being written) until a
// record of r bytes fits under maxBytes, counting their unsent records as
// dropped and overflowed.
func (s *Spool) evictFor(r int64) {
	for len(s.segs) > 1 && s.totalBytes()+r > s.maxBytes {
		lost := s.removeFirst()
		s.dropped += uint64(lost)
		s.overflowed += uint64(lost)
	}
}

func (s *Spool) totalBytes() int64 {
	var n int64
	for _, seg := range s.segs {
		n += seg.size
	}
	return n
}

// removeFirst deletes the oldest segment and returns how many unsent records it held.
func (s *Spool) removeFirst() int {
	first := s.segs[0]
	lost := first.n - s.consumed
	if len(s.segs) == 1 && s.active != nil {
		_ = s.active.Close()
		s.active = nil
	}
	if err := os.Remove(s.segPath(first.index)); err != nil && !os.IsNotExist(err) {
		slog.Error("spool: removing segment", "segment", segName(first.index), "err", err)
	}
	s.segs = s.segs[1:]
	s.disk -= lost
	s.curOff, s.consumed = 0, 0
	s.head = nil
	s.writeCursor()
	return lost
}

// writeCursor records the head position (temp file + rename, no fsync: a crash
// may resend a few messages, which the publisher's dedupe absorbs).
func (s *Spool) writeCursor() {
	idx := s.nextIndex
	if len(s.segs) > 0 {
		idx = s.segs[0].index
	}
	path := filepath.Join(s.dir, cursorFile)
	tmp := path + ".tmp"
	err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %d\n", idx, s.curOff)), 0o600)
	if err == nil {
		err = os.Rename(tmp, path)
	}
	switch {
	case err != nil && !s.cursorFailed:
		s.cursorFailed = true
		slog.Error("spool: cursor write failed; a restart may resend messages", "err", err)
	case err == nil:
		s.cursorFailed = false
	}
}

// Head returns the oldest queued message without removing it.
func (s *Spool) Head() (Msg, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headLocked()
}

func (s *Spool) headLocked() (Msg, bool) {
	// A fully consumed or empty oldest segment is just done, not an error.
	for len(s.segs) > 1 && s.consumed >= s.segs[0].n {
		s.removeFirst()
	}
	for s.disk > 0 {
		if s.head == nil && !s.loadHead() {
			continue // unreadable segment dropped; try the next
		}
		return *s.head, true
	}
	if len(s.tail) > 0 {
		return s.tail[0], true
	}
	return Msg{}, false
}

// loadHead reads the head record of segs[0] (header, then payload, at curOff).
// If it cannot be read the rest of that segment is dropped and false is returned.
func (s *Spool) loadHead() bool {
	seg := s.segs[0]
	m, n, err := readRecordAt(s.segPath(seg.index), s.curOff)
	if err == nil {
		s.head, s.headLen = &m, int64(n)
		return true
	}
	lost := s.removeFirst()
	slog.Error("spool: unreadable segment, dropping its unsent records", "segment", segName(seg.index), "lost", lost, "err", err)
	s.dropped += uint64(lost)
	return false
}

// readRecordAt reads one record at off without loading the whole segment.
func readRecordAt(path string, off int64) (Msg, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return Msg{}, 0, err
	}
	defer f.Close()
	buf := make([]byte, headerLen)
	if _, err := f.ReadAt(buf, off); err != nil {
		return Msg{}, 0, errTorn
	}
	n := int(binary.LittleEndian.Uint32(buf[0:4]))
	if n < payloadMin || n > maxPayload {
		return Msg{}, 0, errCorrupt
	}
	buf = append(buf, make([]byte, n)...)
	if _, err := f.ReadAt(buf[headerLen:], off+headerLen); err != nil {
		return Msg{}, 0, errTorn
	}
	return decodeRecord(buf)
}

// Pop removes the head only if it still has the given seq; it may have been
// dropped for overflow while the sender was publishing it.
func (s *Spool) Pop(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeHead(seq)
}

// Discard removes the head as undeliverable and counts it as dropped.
func (s *Spool) Discard(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.removeHead(seq) {
		s.dropped++
	}
}

func (s *Spool) removeHead(seq uint64) bool {
	m, ok := s.headLocked()
	if !ok || m.Seq != seq {
		return false
	}
	if s.disk == 0 {
		s.tail[0] = Msg{}
		s.tail = s.tail[1:]
		return true
	}
	s.curOff += s.headLen
	s.consumed++
	s.disk--
	s.head = nil
	if s.consumed == s.segs[0].n && len(s.segs) > 1 {
		s.removeFirst() // fully consumed, nothing unsent in it
		return true
	}
	s.writeCursor()
	return true
}

// Len is the number of queued messages.
func (s *Spool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disk + len(s.tail)
}

// Dropped counts messages discarded for any reason (overflow, undeliverable, corrupt).
func (s *Spool) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Overflowed counts messages discarded because the spool was full, excluding
// undeliverable and corrupt ones.
func (s *Spool) Overflowed() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overflowed
}

// Close closes the active segment. Unsent messages stay on disk for the next Open;
// a memory tail does not survive.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil
	}
	err := s.active.Close()
	s.active = nil
	return err
}

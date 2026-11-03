package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
)

// StreamSnapshots reads a host's latest snapshot straight from the stream.
type StreamSnapshots struct{ Stream jetstream.Stream }

// LatestSnapshot implements SnapshotSource.
func (s StreamSnapshots) LatestSnapshot(ctx context.Context, host string) (*asmv1.Snapshot, Meta, error) {
	m, err := s.Stream.GetLastMsgForSubject(ctx, bus.Subject(host, bus.KindSnapshot))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return nil, Meta{}, ErrNoSnapshot
	}
	if err != nil {
		return nil, Meta{}, err
	}
	var snap asmv1.Snapshot
	if err := proto.Unmarshal(m.Data, &snap); err != nil {
		return nil, Meta{}, fmt.Errorf("decode snapshot: %w", err)
	}
	return &snap, Meta{Host: host, Kind: bus.KindSnapshot, StreamSeq: m.Sequence, StreamTime: m.Time}, nil
}

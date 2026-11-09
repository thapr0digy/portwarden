package pg

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/thapr0digy/portwarden/internal/backend/svc"
)

// clean removes NUL bytes and replaces invalid UTF-8, which PostgreSQL text and jsonb
// reject.
func clean(s string) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return s
}

// cleanMessage cleans every string field of m, recursively.
func cleanMessage(m proto.Message) {
	if m != nil {
		cleanReflect(m.ProtoReflect())
	}
}

func cleanReflect(m protoreflect.Message) {
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList():
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				switch fd.Kind() {
				case protoreflect.StringKind:
					l.Set(i, protoreflect.ValueOfString(clean(l.Get(i).String())))
				case protoreflect.MessageKind, protoreflect.GroupKind:
					cleanReflect(l.Get(i).Message())
				}
			}
		case fd.IsMap():
			// No map fields in asm.v1.
		case fd.Kind() == protoreflect.StringKind:
			if c := clean(v.String()); c != v.String() {
				m.Set(fd, protoreflect.ValueOfString(c))
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			cleanReflect(v.Message())
		}
		return true
	})
}

// classify marks database data errors (SQLSTATE class 22 data exception, 23 integrity
// constraint violation) as permanent; everything else stays transient.
func classify(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (strings.HasPrefix(pe.Code, "22") || strings.HasPrefix(pe.Code, "23")) {
		return svc.Permanent(err)
	}
	return err
}

// Quarantine stores a message the inventory will not apply.
func (s *Store) Quarantine(ctx context.Context, streamSeq uint64, subject, why string, data []byte) error {
	_, err := s.exec(ctx, "INSERT INTO quarantine (stream_seq, subject, error, data) VALUES ($1, $2, $3, $4)",
		int64(streamSeq), clean(subject), clean(why), data)
	return err
}

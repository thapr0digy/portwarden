package validate

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// walker visits every set field of a message tree and bounds it: string and bytes
// lengths, repeated and map counts, valid UTF-8 without NUL, finite numbers, valid
// timestamps and durations, then the message's own rule (rules.go).
type walker struct {
	l Limits
}

func (w walker) message(m protoreflect.Message, path string, depth int) *Problem {
	if depth > maxDepth {
		return &Problem{Code: CodeInvalidPayload, Path: path, Reason: "nested too deep"}
	}
	if p := wellKnown(m, path); p != nil {
		return p
	}
	if n := len(m.GetUnknown()); n > w.l.MaxUnknownBytes {
		return &Problem{Code: CodeTooLarge, Path: path, Reason: fmt.Sprintf("%d bytes of unknown fields > %d", n, w.l.MaxUnknownBytes)}
	}
	var bad *Problem
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		bad = w.field(fd, v, join(path, string(fd.Name())), depth)
		return bad == nil
	})
	if bad != nil {
		return bad
	}
	if rule, ok := rules[m.Descriptor().FullName()]; ok {
		if p := rule(m.Interface(), path); p != nil {
			return p
		}
	}
	return nil
}

func (w walker) field(fd protoreflect.FieldDescriptor, v protoreflect.Value, path string, depth int) *Problem {
	maxBytes, maxItems := w.l.fieldLimit(fd)
	switch {
	case fd.IsMap():
		mp := v.Map()
		if mp.Len() > maxItems {
			return tooMany(path, mp.Len(), maxItems)
		}
		var bad *Problem
		mp.Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
			kp := fmt.Sprintf("%s[%q]", path, truncate(k.String()))
			if fd.MapKey().Kind() == protoreflect.StringKind {
				if bad = w.scalar(fd.MapKey(), k.Value(), kp, w.l.MaxString, depth); bad != nil {
					return false
				}
			}
			bad = w.scalar(fd.MapValue(), mv, kp, maxBytes, depth)
			return bad == nil
		})
		return bad
	case fd.IsList():
		list := v.List()
		if list.Len() > maxItems {
			return tooMany(path, list.Len(), maxItems)
		}
		for i := 0; i < list.Len(); i++ {
			if p := w.scalar(fd, list.Get(i), fmt.Sprintf("%s[%d]", path, i), maxBytes, depth); p != nil {
				return p
			}
		}
		return nil
	default:
		return w.scalar(fd, v, path, maxBytes, depth)
	}
}

func (w walker) scalar(fd protoreflect.FieldDescriptor, v protoreflect.Value, path string, maxBytes, depth int) *Problem {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return text(v.String(), path, maxBytes)
	case protoreflect.BytesKind:
		if n := len(v.Bytes()); n > maxBytes {
			return &Problem{Code: CodeTooLarge, Path: path, Reason: fmt.Sprintf("%d bytes > %d", n, maxBytes)}
		}
	case protoreflect.DoubleKind, protoreflect.FloatKind:
		if f := v.Float(); math.IsNaN(f) || math.IsInf(f, 0) {
			return &Problem{Code: CodeInvalidPayload, Path: path, Reason: "not a finite number"}
		}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return w.message(v.Message(), path, depth+1)
	default:
		// Integers, booleans and enums are bounded by their type. An unknown enum
		// number (a newer schema) is read as unspecified, never refused.
	}
	return nil
}

// text bounds a string and refuses invalid UTF-8 and NUL.
func text(s, path string, maxBytes int) *Problem {
	if len(s) > maxBytes {
		return &Problem{Code: CodeTooLarge, Path: path, Reason: fmt.Sprintf("%d bytes > %d", len(s), maxBytes)}
	}
	if !utf8.ValidString(s) {
		return &Problem{Code: CodeInvalidPayload, Path: path, Reason: "not valid UTF-8"}
	}
	if strings.IndexByte(s, 0) >= 0 {
		return &Problem{Code: CodeInvalidPayload, Path: path, Reason: "contains NUL"}
	}
	return nil
}

func wellKnown(m protoreflect.Message, path string) *Problem {
	switch x := m.Interface().(type) {
	case *timestamppb.Timestamp:
		if err := x.CheckValid(); err != nil {
			return &Problem{Code: CodeInvalidPayload, Path: path, Reason: "invalid timestamp"}
		}
	case *durationpb.Duration:
		if err := x.CheckValid(); err != nil {
			return &Problem{Code: CodeInvalidPayload, Path: path, Reason: "invalid duration"}
		}
		if x.AsDuration() < 0 {
			return &Problem{Code: CodeInvalidPayload, Path: path, Reason: "negative duration"}
		}
	}
	return nil
}

func tooMany(path string, n, max int) *Problem {
	return &Problem{Code: CodeTooLarge, Path: path, Reason: fmt.Sprintf("%d items > %d", n, max)}
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// truncate keeps a hostile map key from making an error message large.
func truncate(s string) string {
	const max = 64
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

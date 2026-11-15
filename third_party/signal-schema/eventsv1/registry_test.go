package eventsv1

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// The validators rely on the schema having no recursive message: nesting depth is
// then bounded by the schema's shape. A message that can reach itself breaks that
// assumption.
func TestNoRecursiveMessages(t *testing.T) {
	var visit func(md protoreflect.MessageDescriptor, path []protoreflect.FullName)
	visit = func(md protoreflect.MessageDescriptor, path []protoreflect.FullName) {
		for _, p := range path {
			if p == md.FullName() {
				t.Fatalf("recursive message: %v -> %s", path, md.FullName())
			}
		}
		path = append(path, md.FullName())
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			if fd.IsMap() {
				fd = fd.MapValue()
			}
			if fd.Message() != nil {
				visit(fd.Message(), path)
			}
		}
	}
	for _, m := range []protoreflect.ProtoMessage{&Batch{}, &IngestResponse{}, &StoredEvent{}} {
		visit(m.ProtoReflect().Descriptor(), nil)
	}
}

// Every data case is in the range HasUnknownCase reads as a payload.
func TestDataCasesInRange(t *testing.T) {
	fields := DataOneof().Fields()
	for i := 0; i < fields.Len(); i++ {
		if n := fields.Get(i).Number(); n < firstDataCase || n > lastDataCase {
			t.Errorf("data case %d outside %d-%d", n, firstDataCase, lastDataCase)
		}
	}
}

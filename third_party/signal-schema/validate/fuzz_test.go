package validate

import (
	"testing"
	"time"
)

// FuzzDecodeBinary: the binary batch decoder reads untrusted bytes; it must never panic,
// and every element it returns is either valid or carries a Problem.
func FuzzDecodeBinary(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x02, 0x0a, 0x00})
	f.Add([]byte{0x12, 0x03, 'a', 'b', 'c'})
	f.Fuzz(func(t *testing.T, body []byte) {
		d, err := DecodeBinary(body, Options{Now: func() time.Time { return time.Unix(1762783500, 0) }})
		if err != nil {
			return
		}
		for _, e := range d.Elements {
			if e.Problem == nil && e.Event == nil {
				t.Fatalf("element %d has neither event nor problem", e.Index)
			}
		}
	})
}

// FuzzKey: subject and asset keys come from producers.
func FuzzKey(f *testing.F) {
	for _, s := range []string{"host:0123456789abcdef0123456789abcdef", "ip:198.51.100.7", "dns:*.example.com", "svc:[2001:db8::1]:tcp/443", "url:https://a.example/", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, key string) {
		if scheme, err := Key(key); err == nil && scheme == "" {
			t.Fatal("accepted a key with no scheme")
		}
	})
}

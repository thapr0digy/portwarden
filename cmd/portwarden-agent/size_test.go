package main

import "testing"

func TestParseSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"64MiB", 64 << 20, false},
		{"1KiB", 1 << 10, false},
		{"2GiB", 2 << 30, false},
		{"4096", 4096, false},
		{" 8MiB ", 8 << 20, false},
		{"", 0, true},
		{"0", 0, true},
		{"0MiB", 0, true},
		{"-1", 0, true},
		{"-1MiB", 0, true},
		{"MiB", 0, true},
		{"10MB", 0, true},
		{"10mib", 0, true},
		{"1.5MiB", 0, true},
		{"10 MiB", 0, true},
		{"9223372036854775807GiB", 0, true},
		{"9223372036854775808", 0, true},
	}
	for _, tt := range tests {
		got, err := parseSize(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("parseSize(%q) = %d, %v; want %d, err %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

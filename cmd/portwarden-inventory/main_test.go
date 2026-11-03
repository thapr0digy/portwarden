package main

import "testing"

func TestCheckListen(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:8740": true, "[::1]:1": true, "localhost:1": true, "0.0.0.0:8740": false, "10.0.0.1:1": false} {
		if err := checkListen(addr, false); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if err := checkListen("0.0.0.0:8740", true); err != nil {
		t.Fatal(err)
	}
}

// Package probes loads the listener eBPF programs and turns their ring buffer
// events into model.Observations.
package probes

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -tags linux -type event listen ../../bpf/listen.bpf.c -- -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -tags linux -type conn_key -type conn_val proxyconn ../../bpf/proxyconn.bpf.c -- -I../../bpf

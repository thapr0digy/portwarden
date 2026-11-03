//go:build !linux

package rootfs

// Open returns Walker(root) on platforms without openat2.
func Open(root string) (FS, error) { return Walker(root), nil }

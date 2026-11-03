//go:build linux

package tamper

import (
	"fmt"
	"io/fs"
	"syscall"
)

// signature identifies a file version: device, inode, size, mode, mtime and ctime. A
// replaced file (new inode) or an in-place write (new ctime) changes it.
func signature(fi fs.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf("%d/%v/%d", fi.Size(), fi.Mode(), fi.ModTime().UnixNano())
	}
	return fmt.Sprintf("%d:%d/%d/%v/%d.%d/%d.%d", st.Dev, st.Ino, fi.Size(), fi.Mode(),
		st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec)
}

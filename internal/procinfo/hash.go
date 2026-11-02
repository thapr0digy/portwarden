package procinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"syscall"
	"time"
)

// maxHashCache bounds the hash cache; on overflow an arbitrary entry is dropped.
const maxHashCache = 4096

// fileID identifies one version of an executable file. ctime is part of it
// because mtime can be set back by the file's owner; ctime cannot.
type fileID struct {
	dev, ino     uint64
	size         int64
	mtime, ctime time.Time
}

func idOf(fi os.FileInfo) (fileID, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{
		dev: uint64(st.Dev), ino: uint64(st.Ino), size: fi.Size(),
		mtime: fi.ModTime(), ctime: ctimeOf(st),
	}, true
}

// hashExe returns the sha256 of the file behind exePath (a /proc/<pid>/exe link,
// which names the file actually executed even if it was replaced on disk).
// It returns "" when the file is unreadable or larger than hashMax. The cache
// key comes from the opened file, so it names the bytes that are hashed.
func (r *Resolver) hashExe(exePath string) string {
	f, err := r.open(exePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > r.hashMax {
		return ""
	}
	id, ok := idOf(fi)
	if !ok {
		return ""
	}
	r.mu.Lock()
	sum, hit := r.hashes[id]
	r.mu.Unlock()
	if hit {
		return sum
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, r.hashMax+1))
	if err != nil || n > r.hashMax {
		return "" // unreadable, or grew past hashMax after the Stat
	}
	sum = hex.EncodeToString(h.Sum(nil))

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hashes) >= maxHashCache {
		for k := range r.hashes {
			delete(r.hashes, k)
			break
		}
	}
	r.hashes[id] = sum
	return sum
}

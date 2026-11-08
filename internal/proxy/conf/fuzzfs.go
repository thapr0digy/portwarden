package conf

import (
	"bytes"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

// The fuzz targets of the proxy loaders take a file tree packed into one byte string:
// path NUL content NUL path NUL content ..., the first path being the main config.
// EncodeFiles and DecodeFiles convert between that and a MemFS; LoadTree reads a
// recorded tree (testdata/<case>/root) to seed them.

// EncodeFiles packs fsys with main first, then the other paths sorted.
func EncodeFiles(main string, fsys MemFS) []byte {
	var b bytes.Buffer
	put := func(p string) {
		b.WriteString(p)
		b.WriteByte(0)
		b.Write(fsys[p])
		b.WriteByte(0)
	}
	put(main)
	rest := make([]string, 0, len(fsys))
	for p := range fsys {
		if p != main {
			rest = append(rest, p)
		}
	}
	slices.Sort(rest)
	for _, p := range rest {
		put(p)
	}
	return b.Bytes()
}

// DecodeFiles unpacks data into a MemFS and its main path. Every path is made absolute
// and clean; a repeated path keeps its first content; a trailing path without content
// is an empty file. An input with no path yields main "/" (a directory, so no file).
func DecodeFiles(data []byte) (main string, fsys MemFS) {
	fsys = MemFS{}
	parts := bytes.Split(data, []byte{0})
	for i := 0; i < len(parts); i += 2 {
		p := path.Clean("/" + strings.TrimLeft(string(parts[i]), "/"))
		if main == "" {
			main = p
		}
		if _, dup := fsys[p]; dup || p == "/" {
			continue
		}
		var content []byte
		if i+1 < len(parts) {
			content = parts[i+1]
		}
		fsys[p] = content
	}
	if main == "" {
		main = "/"
	}
	return main, fsys
}

// LoadTree reads every regular file under root as a process inside it sees it
// (symlinks followed inside root), keyed by its absolute in-root path.
func LoadTree(root string) (MemFS, error) {
	w := rootfs.Walker(root)
	out := MemFS{}
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if depth > MaxDepth {
			return fmt.Errorf("%s: deeper than %d", dir, MaxDepth)
		}
		names, err := w.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, n := range names {
			p := path.Join(dir, n)
			in, err := w.Stat(p)
			if err != nil {
				return err
			}
			if in.Dir {
				if err := walk(p, depth+1); err != nil {
					return err
				}
				continue
			}
			b, err := w.ReadFile(p)
			if err != nil {
				return err
			}
			out[p] = b
		}
		return nil
	}
	if err := walk("/", 0); err != nil {
		return nil, fmt.Errorf("load tree %s: %w", root, err)
	}
	return out, nil
}

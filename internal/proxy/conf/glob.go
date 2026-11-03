package conf

import (
	"path"
	"strings"
)

// HasMeta reports whether a path has glob metacharacters.
func HasMeta(p string) bool { return strings.ContainsAny(p, "*?[") }

// Glob expands an absolute pattern as glob(3) without flags does (and as Apache's
// wildcard includes do): metacharacters in any component, results sorted per
// directory, and a wildcard never matches a leading dot unless the pattern component
// starts with one. Every directory listed is added to r's watch list, so a file
// appearing there is noticed.
func Glob(fsys FS, r *Reader, pattern string) []string {
	parts := splitAbs(pattern)
	paths := []string{"/"}
	for i, c := range parts {
		last := i == len(parts)-1
		var next []string
		for _, dir := range paths {
			if !HasMeta(c) {
				p := path.Join(dir, c)
				in, err := fsys.Stat(p)
				switch {
				case err != nil:
					r.Watch(p) // noticed when it appears
				case last || in.Dir:
					next = append(next, p)
				}
				continue
			}
			r.Watch(dir)
			names, err := fsys.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, n := range names {
				if strings.HasPrefix(n, ".") && !strings.HasPrefix(c, ".") {
					continue
				}
				if ok, _ := path.Match(c, n); !ok {
					continue
				}
				p := path.Join(dir, n)
				// A matching last component is returned without a stat, as glob(3)
				// does: a dangling symlink is included and fails to open later.
				if !last {
					if in, err := fsys.Stat(p); err != nil || !in.Dir {
						continue
					}
				}
				next = append(next, p)
			}
		}
		paths = next
		if len(paths) == 0 {
			break
		}
	}
	return paths
}

func splitAbs(p string) []string {
	var out []string
	for _, c := range strings.Split(path.Clean(p), "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

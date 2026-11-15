package access

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/slidehq/signal/schema/eventsv1"
)

const (
	// Sudoers is sudo's main policy file (mode 0440 root on Debian and Ubuntu: the agent
	// usually cannot read it); SudoersDir is the drop-in directory it includes, whose
	// files Ansible's base role writes 0644.
	Sudoers    = "/etc/sudoers"
	SudoersDir = "/etc/sudoers.d"
	// maxSudoersFiles bounds the files one policy may pull in.
	maxSudoersFiles = 256
	// maxAliasDepth bounds User_Alias expansion.
	maxAliasDepth = 8
)

// sudoPolicy is what the readable sudoers files grant, by presence: user specifications
// and User_Alias definitions, never a rule's text.
type sudoPolicy struct {
	aliases map[string][]string
	specs   []userSpec
	// unread names the first file that could not be read ("" when every file was read).
	unread error
	files  int
}

// userSpec is one user specification: who it names and what it grants.
type userSpec struct {
	users         []string
	nopasswd, all bool
}

// readSudoPolicy reads /etc/sudoers and what it includes; when /etc/sudoers itself is
// unreadable it still reads /etc/sudoers.d (Debian's and Ubuntu's include), so a drop-in's
// rule is seen, while the policy stays incomplete (unread set).
func readSudoPolicy(root fs.FS) *sudoPolicy {
	p := &sudoPolicy{aliases: map[string][]string{}}
	if !p.file(root, Sudoers) {
		p.dir(root, SudoersDir)
	}
	return p
}

// file reads one sudoers file; false when it could not be read.
func (p *sudoPolicy) file(root fs.FS, name string) bool {
	if p.files++; p.files > maxSudoersFiles {
		p.noteUnread(errors.New(name + ": too many sudoers files"))
		return false
	}
	data, err := readFile(root, name)
	if err != nil {
		p.noteUnread(err)
		return false
	}
	p.parse(string(data), func(dir bool, target string) {
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(name), target)
		}
		if dir {
			p.dir(root, target)
		} else {
			p.file(root, target)
		}
	})
	return true
}

// dir reads an included directory as sudo does: every file whose name has no "." and does
// not end in "~", in lexical order.
func (p *sudoPolicy) dir(root fs.FS, name string) {
	entries, err := fs.ReadDir(root, fsPath(name))
	if err != nil {
		p.noteUnread(pathError(name, err))
		return
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.Contains(n, ".") || strings.HasSuffix(n, "~") {
			continue
		}
		p.file(root, path.Join(name, n))
	}
}

func (p *sudoPolicy) noteUnread(err error) {
	if p.unread == nil {
		p.unread = err
	}
}

var (
	listSepRe = regexp.MustCompile(`\s*,\s*`)
	runasRe   = regexp.MustCompile(`\([^)]*\)`)
	// tagRe is a command tag (NOPASSWD:, SETENV:, …); optionRe an option (CWD=…, TIMEOUT=…).
	tagRe    = regexp.MustCompile(`^([A-Z_]+):\s*`)
	optionRe = regexp.MustCompile(`^(CWD|CHROOT|ROLE|TYPE|TIMEOUT|NOTBEFORE|NOTAFTER|APPARMOR_PROFILE)=\S+\s*`)
)

// parse reads one file's statements; include is called for each include directive.
func (p *sudoPolicy) parse(text string, include func(dir bool, target string)) {
	for _, line := range sudoLines(text) {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "@include" || f[0] == "#include" || f[0] == "@includedir" || f[0] == "#includedir":
			if len(f) == 2 {
				include(strings.HasSuffix(f[0], "dir"), f[1])
			}
		case strings.HasPrefix(f[0], "Defaults"), f[0] == "Runas_Alias", f[0] == "Host_Alias",
			f[0] == "Cmnd_Alias", f[0] == "Cmd_Alias":
		case f[0] == "User_Alias":
			p.userAliases(strings.TrimSpace(strings.TrimPrefix(line, "User_Alias")))
		default:
			p.userSpec(line)
		}
	}
}

// sudoLines joins continued lines and drops comments ("#" at a word's start that is not
// an include directive or a uid such as #1000).
func sudoLines(text string) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimRight(raw, " \t\r")
		if cont, ok := strings.CutSuffix(raw, `\`); ok {
			cur.WriteString(cont)
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(raw)
		out = append(out, stripSudoComment(cur.String()))
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, stripSudoComment(cur.String()))
	}
	return out
}

func stripSudoComment(line string) string {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "#include ") || strings.HasPrefix(t, "#includedir ") {
		return t
	}
	for i := 0; i < len(line); i++ {
		if line[i] != '#' || (i > 0 && line[i-1] != ' ' && line[i-1] != '\t' && line[i-1] != ',') {
			continue
		}
		if i+1 < len(line) && line[i+1] >= '0' && line[i+1] <= '9' {
			continue
		}
		return line[:i]
	}
	return line
}

// userAliases reads "NAME = a, b : NAME2 = c".
func (p *sudoPolicy) userAliases(defs string) {
	for _, def := range strings.Split(defs, ":") {
		name, list, ok := strings.Cut(def, "=")
		if !ok {
			continue
		}
		p.aliases[strings.TrimSpace(name)] = listSepRe.Split(strings.TrimSpace(list), -1)
	}
}

// userSpec reads "users hosts = [(runas)] [TAGS:] commands".
func (p *sudoPolicy) userSpec(line string) {
	who, grants, ok := strings.Cut(line, "=")
	if !ok {
		return
	}
	f := strings.Fields(listSepRe.ReplaceAllString(strings.TrimSpace(who), ","))
	if len(f) < 2 {
		return
	}
	spec := userSpec{users: strings.Split(f[0], ",")}
	nopasswd := false
	for _, item := range strings.Split(runasRe.ReplaceAllString(grants, " "), ",") {
		item = strings.TrimSpace(item)
		for {
			if m := tagRe.FindStringSubmatch(item); m != nil {
				switch m[1] {
				case "NOPASSWD":
					nopasswd = true
				case "PASSWD":
					nopasswd = false
				}
				item = item[len(m[0]):]
				continue
			}
			if m := optionRe.FindString(item); m != "" {
				item = item[len(m):]
				continue
			}
			break
		}
		if item == "" || strings.HasPrefix(item, "!") {
			continue
		}
		spec.nopasswd = spec.nopasswd || nopasswd
		spec.all = spec.all || item == "ALL"
	}
	p.specs = append(p.specs, spec)
}

// rule is what the policy grants u, by presence. known is false when part of the policy
// could not be read and no readable rule names u: then absence cannot be told.
func (p *sudoPolicy) rule(u user, groups groupDB) (rule *eventsv1.SudoRule, known bool) {
	rule = &eventsv1.SudoRule{}
	for _, s := range p.specs {
		if !p.names(s.users, u, groups, 0) {
			continue
		}
		rule.Present = true
		rule.Nopasswd = rule.Nopasswd || s.nopasswd
		rule.AllCommands = rule.AllCommands || s.all
	}
	return rule, rule.Present || p.unread == nil
}

// names reports whether a user list names u: the name, ALL, %group, #uid, %#gid or a
// User_Alias. A negated item (!name) is not read as a match.
func (p *sudoPolicy) names(list []string, u user, groups groupDB, depth int) bool {
	for _, item := range list {
		item = strings.TrimSpace(item)
		switch {
		case item == "" || strings.HasPrefix(item, "!"):
		case item == "ALL" || item == u.name || item == "#"+u.uid:
			return true
		case strings.HasPrefix(item, "%#"):
			if item[2:] == u.gid || slices.Contains(groups.gidsOf(u), item[2:]) {
				return true
			}
		case strings.HasPrefix(item, "%:"):
		case strings.HasPrefix(item, "%"):
			if groups.member(item[1:], u) {
				return true
			}
		default:
			if a, ok := p.aliases[item]; ok && depth < maxAliasDepth && p.names(a, u, groups, depth+1) {
				return true
			}
		}
	}
	return false
}

package nginx

import "strings"

type tokKind int

const (
	tokWord tokKind = iota
	tokSemi
	tokOpen
	tokClose
)

type token struct {
	kind tokKind
	text string
	line int
}

// lex splits a config file as ngx_conf_read_token does: whitespace separates words; ';',
// '{' and '}' end them; '#' at the start of a word comments to the end of the line;
// single- and double-quoted strings may hold any of those; a backslash escapes the next
// character; "${name}" is part of a word. An unterminated quote ends the file
// (unterminated is then true; nginx refuses such a file).
func lex(src string) (out []token, unterminated bool) {
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == ';':
			out = append(out, token{tokSemi, ";", line})
			i++
		case c == '{':
			out = append(out, token{tokOpen, "{", line})
			i++
		case c == '}':
			out = append(out, token{tokClose, "}", line})
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			start := line
			var b strings.Builder
			i++
			for i < len(src) && src[i] != c {
				if src[i] == '\\' && i+1 < len(src) {
					b.WriteString(unescape(src[i+1]))
					if src[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if src[i] == '\n' {
					line++
				}
				b.WriteByte(src[i])
				i++
			}
			if i >= len(src) {
				unterminated = true
			}
			i++ // closing quote
			out = append(out, token{tokWord, b.String(), start})
		default:
			start := line
			var b strings.Builder
			for i < len(src) {
				c := src[i]
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '{' || c == '}' {
					// "${" opens a variable name, not a block.
					if c == '{' && b.Len() > 0 && strings.HasSuffix(b.String(), "$") {
						end := strings.IndexByte(src[i:], '}')
						if end > 0 {
							b.WriteString(src[i : i+end+1])
							i += end + 1
							continue
						}
					}
					break
				}
				if c == '\\' && i+1 < len(src) {
					b.WriteString(unescape(src[i+1]))
					i += 2
					continue
				}
				b.WriteByte(c)
				i++
			}
			out = append(out, token{tokWord, b.String(), start})
		}
	}
	return out, unterminated
}

// unescape is what nginx keeps of "\c": \" \' \\ \t \r \n are unescaped, any other
// character keeps its backslash.
func unescape(c byte) string {
	switch c {
	case '"', '\'', '\\':
		return string(c)
	case 't':
		return "\t"
	case 'r':
		return "\r"
	case 'n':
		return "\n"
	}
	return "\\" + string(c)
}

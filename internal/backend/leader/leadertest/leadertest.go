// Package leadertest checks, for tests, that a store package sends every write through
// its fenced transaction helper (leader.PGLease.Fence), so an old leader cannot commit.
package leadertest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// T is the part of *testing.T the check uses.
type T interface {
	Helper()
	Errorf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

var writeSQL = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|TRUNCATE|ALTER|CREATE|DROP)\b`)

// UnfencedWrites parses the non-test Go files in dir and fails t for every call on the
// store's pool (a selector ending in ".pool.<Method>") that can write outside the
// functions named in allowed: Exec, Begin, BeginTx, CopyFrom and SendBatch always, and
// Query/QueryRow whose literal SQL writes.
func UnfencedWrites(t T, dir string, allowed ...string) {
	t.Helper()
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, d := range file.Decls {
			fn, isFunc := d.(*ast.FuncDecl)
			if !isFunc || fn.Body == nil || ok[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel {
					return true
				}
				inner, isInner := sel.X.(*ast.SelectorExpr)
				if !isInner || inner.Sel.Name != "pool" {
					return true
				}
				switch sel.Sel.Name {
				case "Exec", "Begin", "BeginTx", "CopyFrom", "SendBatch":
					t.Errorf("%s: %s calls pool.%s outside the fenced helper", fset.Position(call.Pos()), fn.Name.Name, sel.Sel.Name)
				case "Query", "QueryRow":
					if len(call.Args) > 1 {
						if lit, isLit := call.Args[1].(*ast.BasicLit); isLit && lit.Kind == token.STRING {
							if sql, err := strconv.Unquote(lit.Value); err == nil && writeSQL.MatchString(sql) {
								t.Errorf("%s: %s writes through pool.%s outside the fenced helper", fset.Position(call.Pos()), fn.Name.Name, sel.Sel.Name)
							}
						}
					}
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatalf("no Go files in %s", dir)
	}
}

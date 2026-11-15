package scan

import (
	"fmt"
	"path/filepath"

	"github.com/yekunsong/Packout/internal/fsx"
	"github.com/yekunsong/Packout/internal/manifest"
	"github.com/yekunsong/Packout/internal/profile"
)

// resolveRoots builds root instances from cfg.Roots, falling back to the
// profile templates for roles the caller did not bind. Unresolvable templates
// become root_unresolved notes rather than a fatal error, so one bad root does
// not hide the rest of the machine.
func (s *scanner) resolveRoots() error {
	seen := make(map[string]int) // role -> next instance suffix
	bindings := s.cfg.Roots
	if len(bindings) == 0 {
		for _, role := range s.cfg.Profile.RootOrder {
			bindings = append(bindings, RootBinding{Role: role, Origin: "profile"})
		}
	}
	for _, b := range bindings {
		role := b.Role
		if role == "" {
			return fmt.Errorf("%w: root binding without role", ErrConfig)
		}
		if _, ok := s.cfg.Profile.Roots[role]; !ok {
			return fmt.Errorf("%w: root role %q is not declared by profile", ErrConfig, role)
		}
		seen[role]++
		name := b.Name
		if name == "" {
			if seen[role] == 1 {
				name = role
			} else {
				name = fmt.Sprintf("%s#%d", role, seen[role])
			}
		}
		if s.rootNamed(name) != nil {
			return fmt.Errorf("%w: duplicate root instance %q", ErrConfig, name)
		}
		tmpl := b.Path
		origin := b.Origin
		if tmpl == "" {
			tmpl = s.cfg.Profile.Roots[role].ForOS(s.goos)
			if origin == "" {
				origin = "profile"
			}
		} else if origin == "" {
			origin = "cli"
		}
		expanded, err := profile.ExpandTemplate(tmpl)
		if err != nil {
			s.rootNotes = append(s.rootNotes, manifest.Note{
				Code:   "root_unresolved",
				Detail: fmt.Sprintf("root %s: %v", role, err),
			})
			continue
		}
		abs, err := fsx.Abs(filepath.FromSlash(expanded))
		if err != nil {
			s.rootNotes = append(s.rootNotes, manifest.Note{
				Code:   "root_unresolved",
				Detail: fmt.Sprintf("root %s: %v", role, err),
			})
			continue
		}
		if origin == "" {
			origin = "profile"
		}
		s.roots = append(s.roots, rootInstance{
			name: name, role: role, path: abs, origin: origin, instance: seen[role], order: len(s.roots),
		})
	}
	return nil
}

func (s *scanner) rootNamed(name string) *rootInstance {
	for i := range s.roots {
		if s.roots[i].name == name {
			return &s.roots[i]
		}
	}
	return nil
}

// rootContaining returns the first declared root containing p, if any.
func (s *scanner) rootContaining(p string) *rootInstance {
	for i := range s.roots {
		if fsx.Within(s.roots[i].path, p) {
			return &s.roots[i]
		}
	}
	return nil
}

// rootResolver maps an entry-relative or absolute declaration to an absolute
// path and the root instance it belongs to. Absolute paths outside every root
// use the external instance.
func (s *scanner) rootResolver(root *rootInstance, decl string) (string, *rootInstance, error) {
	absDecl, err := isAbsDecl(decl)
	if err != nil {
		return "", nil, err
	}
	if absDecl {
		p, err := absPath(decl)
		if err != nil {
			return "", nil, err
		}
		return p, root, nil
	}
	if root != nil {
		return joinRoot(root.path, decl), root, nil
	}
	p, err := absPath(decl)
	if err != nil {
		return "", nil, err
	}
	if r := s.rootContaining(p); r != nil {
		return p, r, nil
	}
	return p, nil, nil
}

// relOf returns the declaration-relative path of p under root.
func (s *scanner) relOf(root *rootInstance, p string) string {
	if root == nil {
		return ""
	}
	return slashRel(root.path, p)
}

func (s *scanner) rootByUnit(root string) *rootInstance {
	return s.rootNamed(root)
}

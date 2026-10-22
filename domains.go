package whalewall

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"go.uber.org/zap/zapcore"
	"golang.org/x/net/idna"
)

// domainKind is how a domainPattern matches names below its suffix. Rules
// list patterns in the "domains" key, for example:
//
//	domains: [example.com, "*.example.com", "**.cdn.example.com"]
type domainKind uint8

const (
	// domainExact matches only the exact name.
	domainExact domainKind = iota
	// domainWildcard matches exactly one label below the suffix.
	domainWildcard
	// domainNested matches one or more labels below the suffix.
	domainNested
)

// the limits of DNS names: 253 characters in total (without the trailing
// dot), 63 per label
const (
	maxDomainLen = 253
	maxLabelLen  = 63
)

// domainPattern is a single entry of a rule's "domains" list. The
// pattern never matches its own suffix: "*.example.com" and
// "**.example.com" do not match "example.com".
type domainPattern struct {
	kind   domainKind
	suffix string
}

// parseDomainPattern parses and normalizes a domain pattern. Names are
// lower-cased, converted to their ASCII (punycode) form and have a
// trailing dot stripped.
func parseDomainPattern(s string) (domainPattern, error) {
	var p domainPattern

	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	// "**." has to be checked before "*." as it starts with it
	switch {
	case strings.HasPrefix(s, "**."):
		p.kind = domainNested
		s = s[3:]
	case strings.HasPrefix(s, "*."):
		p.kind = domainWildcard
		s = s[2:]
	}
	if s == "" {
		return domainPattern{}, errors.New("domain is empty")
	}
	// a wildcard anywhere else ("a*.example.com", "foo.*.com") would need
	// partial label matching, which is deliberately not supported
	if strings.Contains(s, "*") {
		return domainPattern{}, fmt.Errorf(`invalid domain %q: "*" and "**" are only allowed as the entire first label`, s)
	}

	name, err := normalizeDomain(s)
	if err != nil {
		return domainPattern{}, err
	}
	p.suffix = name

	return p, nil
}

// normalizeDomain validates a name and returns its lower-case ASCII form
// without a trailing dot. Every name that is compared to a pattern goes
// through the same form, so unicode names, upper case and trailing dots can't
// make a name match, or not match, differently than the administrator
// meant.
func normalizeDomain(s string) (string, error) {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", errors.New("domain is empty")
	}
	if strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return "", fmt.Errorf("invalid domain %q: empty label", s)
	}
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("invalid domain %q: not valid UTF-8", s)
	}
	// internationalized names become punycode ("bücher.de" is
	// "xn--bcher-kva.de"), which is what appears in DNS queries
	name, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", s, err)
	}
	name = asciiLower(name)
	// the result must be a name that can be matched, and converting it
	// again must not change it
	if !plainName(name) {
		return "", fmt.Errorf("invalid domain %q: contains characters that are not allowed in a name", s)
	}
	if again, err := idna.Lookup.ToASCII(name); err != nil || again != name {
		return "", fmt.Errorf("invalid domain %q: not a valid name", s)
	}
	if len(name) > maxDomainLen {
		return "", fmt.Errorf("invalid domain %q: longer than %d characters", s, maxDomainLen)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > maxLabelLen {
			return "", fmt.Errorf("invalid domain %q: label longer than %d characters", s, maxLabelLen)
		}
	}

	return name, nil
}

// matches reports whether name, which must be normalized, is matched by
// the pattern. For the pattern "*.example.com":
//
//	www.example.com        matches
//	a.b.example.com        does not match (more than one label)
//	example.com            does not match (the apex)
//
// "**.example.com" also matches a.b.example.com, but not example.com.
// The match is on whole labels: "badexample.com" matches neither, as the
// suffix is compared with the dot in front of it.
func (p domainPattern) matches(name string) bool {
	switch p.kind {
	case domainExact:
		return name == p.suffix
	case domainWildcard:
		prefix, ok := strings.CutSuffix(name, "."+p.suffix)
		return ok && prefix != "" && !strings.Contains(prefix, ".")
	case domainNested:
		prefix, ok := strings.CutSuffix(name, "."+p.suffix)
		return ok && prefix != ""
	default:
		return false
	}
}

// String returns the pattern in the form it is written in rules.
func (p domainPattern) String() string {
	switch p.kind {
	case domainWildcard:
		return "*." + p.suffix
	case domainNested:
		return "**." + p.suffix
	default:
		return p.suffix
	}
}

// MarshalText, UnmarshalText, MarshalBinary and UnmarshalBinary let
// patterns be read from the YAML of the rules label and stored in the
// state database in their normalized form. Reading always validates.
func (p domainPattern) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

func (p *domainPattern) UnmarshalText(text []byte) error {
	parsed, err := parseDomainPattern(string(text))
	if err != nil {
		return err
	}
	*p = parsed

	return nil
}

func (p domainPattern) MarshalBinary() ([]byte, error) {
	return p.MarshalText()
}

func (p *domainPattern) UnmarshalBinary(data []byte) error {
	return p.UnmarshalText(data)
}

// domainsList is the "domains" list of a rule.
type domainsList []domainPattern

func (d domainsList) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, p := range d {
		enc.AppendString(p.String())
	}

	return nil
}

// matches reports whether any pattern matches name. name does not need to
// be normalized.
func (d domainsList) matches(name string) bool {
	name = asciiLower(strings.TrimSuffix(name, "."))
	// names with control characters, empty labels or bytes above ASCII are
	// not matched by any pattern, wildcards included
	if !plainName(name) {
		return false
	}
	for _, p := range d {
		if p.matches(name) {
			return true
		}
	}

	return false
}

// plainName reports whether name consists of non-empty labels of
// printable ASCII characters. Names that don't, such as ones with
// control characters or non-ASCII bytes, can't be what an administrator
// allowed and are never matched, not even by wildcards.
func plainName(name string) bool {
	if name == "" || name[0] == '.' || name[len(name)-1] == '.' {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if c <= ' ' || c >= 0x7f {
			return false
		}
		if c == '.' && name[i-1] == '.' {
			return false
		}
	}
	return true
}

// asciiLower lower-cases ASCII letters only. strings.ToLower also folds
// some non-ASCII characters to ASCII ones (the Kelvin sign U+212A becomes
// "k"), which would make a different name match a pattern.
func asciiLower(s string) string {
	for i := range len(s) {
		if c := s[i]; 'A' <= c && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

package detect

import (
	"bytes"
	"net/netip"
	"regexp"
	"strings"
)

// Personal-data detectors. They are the false-positive-prone ones, so each
// has a context check and the clean corpus has a trap for it.

func isWordByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func byteAt(b []byte, i int) (byte, bool) {
	if i < 0 || i >= len(b) {
		return 0, false
	}
	return b[i], true
}

// ---- email ----

var fileExtTLD = map[string]bool{
	"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "webp": true, "ico": true,
	"css": true, "js": true, "json": true, "html": true, "htm": true, "xml": true, "txt": true,
	"md": true, "go": true, "py": true, "java": true, "so": true, "dll": true, "exe": true,
}

func email() *Detector {
	label := `[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?`
	return &Detector{
		ID:   "email",
		Desc: "email address",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`[A-Za-z0-9._%+-]+@` + label + `(?:\.` + label + `)*\.[A-Za-z]{2,}`),
		},
		Hints:     []string{"@"},
		Pseudonym: true,
		Canonical: bytes.ToLower,
		Validate:  validEmail,
		Check: func(line []byte, start, _ int) bool {
			// ssh://git@host is URL userinfo, not an address.
			return start < 2 || line[start-2] != '/' || line[start-1] != '/'
		},
	}
}

func validEmail(b []byte) bool {
	at := bytes.LastIndexByte(b, '@')
	local, domain := string(b[:at]), string(b[at+1:])
	if local == "git" || len(b) > 254 { // git@github.com: scp-style ssh remotes
		return false
	}
	tld := strings.ToLower(domain[strings.LastIndexByte(domain, '.')+1:])
	return !fileExtTLD[tld] // icon@2x.png
}

// ---- IPv4 ----

func ipv4() *Detector {
	return &Detector{
		ID:   "ipv4",
		Desc: "IPv4 address (loopback and 0.0.0.0 are left alone)",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`),
		},
		Hints:     []string{"."},
		Pseudonym: true,
		Validate:  validIPv4,
		Check: func(line []byte, start, end int) bool {
			if c, ok := byteAt(line, start-1); ok && (isWordByte(c) || c == '.') {
				return false // part of a longer number, version or name
			}
			if versionContext(line, start) {
				return false
			}
			c, ok := byteAt(line, end)
			if !ok {
				return true
			}
			if isWordByte(c) {
				return false
			}
			if c == '.' { // a sentence-ending dot is fine; 1.2.3.4.5 or 1.2.3.4.example is not
				n, ok := byteAt(line, end+1)
				return !ok || !isWordByte(n)
			}
			return true
		},
	}
}

// versionContext spots "Chrome/126.0.0.0" (a single slash, unlike "http://")
// and "version: 1.2.3.4" before a dotted number.
func versionContext(line []byte, start int) bool {
	if start >= 1 && line[start-1] == '/' && (start < 2 || line[start-2] != '/') {
		return true
	}
	i := start
	for i > 0 && (line[i-1] == ' ' || line[i-1] == ':' || line[i-1] == '=') {
		i--
	}
	j := i
	for j > 0 && (line[j-1]|0x20 >= 'a' && line[j-1]|0x20 <= 'z') {
		j--
	}
	switch strings.ToLower(string(line[j:i])) {
	case "version", "ver", "v":
		return true
	}
	return false
}

func validIPv4(b []byte) bool {
	parts := strings.Split(string(b), ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) > 1 && p[0] == '0' { // 01.02.03.04 is not how addresses are logged
			return false
		}
		n := 0
		for _, c := range []byte(p) {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	a, err := netip.ParseAddr(string(b))
	return err == nil && !a.IsLoopback() && !a.IsUnspecified()
}

// ---- IPv6 ----

func ipv6() *Detector {
	h := `[0-9A-Fa-f]{1,4}`
	return &Detector{
		ID:   "ipv6",
		Desc: "IPv6 address (::1 and :: are left alone)",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?:[0-9A-Fa-f]{0,4}:){2,7}` + h + `|(?:` + h + `:){1,7}:`),
		},
		Hints:     []string{"::", ":"},
		Pseudonym: true,
		Canonical: func(b []byte) []byte {
			if a, err := netip.ParseAddr(string(b)); err == nil {
				return []byte(a.String())
			}
			return bytes.ToLower(b)
		},
		Validate: validIPv6,
		Check: func(line []byte, start, end int) bool {
			if c, ok := byteAt(line, start-1); ok && (isWordByte(c) || c == ':' || c == '.') {
				return false // std::vector, Foo::bar, a longer colon-separated run
			}
			if c, ok := byteAt(line, end); ok && (isWordByte(c) || c == ':') {
				return false
			}
			return true
		},
	}
}

func validIPv6(b []byte) bool {
	// "a::b" is a valid address but far more likely an identifier path.
	if len(b) < 7 {
		return false
	}
	a, err := netip.ParseAddr(string(b))
	return err == nil && a.Is6() && !a.Is4In6() && !a.IsLoopback() && !a.IsUnspecified()
}

// ---- credit card ----

func creditCard() *Detector {
	return &Detector{
		ID:   "credit-card",
		Desc: "payment card number (Luhn-valid, known issuer prefix)",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`[0-9]{13,19}`),
			regexp.MustCompile(`[0-9]{4}(?:[ -][0-9]{4}){2,3}(?:[ -][0-9]{1,3})?`),
			regexp.MustCompile(`3[47][0-9]{2}[ -][0-9]{6}[ -][0-9]{5}`),
		},
		Pre:      hasDigitRun(13),
		Validate: validCard,
		Check: func(line []byte, start, end int) bool {
			if c, ok := byteAt(line, start-1); ok && isWordByte(c) {
				return false
			}
			if c, ok := byteAt(line, end); ok && isWordByte(c) {
				return false
			}
			return true
		},
	}
}

// hasDigitRun reports whether the line holds n digits, allowing the single
// space or dash separators cards are written with. It is the prefilter.
func hasDigitRun(n int) func([]byte) bool {
	return func(line []byte) bool {
		run := 0
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case isDigit(c):
				run++
				if run >= n {
					return true
				}
			case (c == ' ' || c == '-') && run > 0 && i+1 < len(line) && isDigit(line[i+1]):
			default:
				run = 0
			}
		}
		return false
	}
}

func validCard(b []byte) bool {
	digits := make([]byte, 0, len(b))
	for _, c := range b {
		if isDigit(c) {
			digits = append(digits, c)
		}
	}
	return len(digits) >= 13 && len(digits) <= 19 && knownIssuer(digits) && luhn(digits)
}

func luhn(d []byte) bool {
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// knownIssuer checks the issuer prefix and the lengths that issuer uses.
func knownIssuer(d []byte) bool {
	n := len(d)
	p := func(k int) int {
		v := 0
		for _, c := range d[:k] {
			v = v*10 + int(c-'0')
		}
		return v
	}
	switch {
	case d[0] == '4': // Visa
		return n == 13 || n == 16 || n == 19
	case p(2) >= 51 && p(2) <= 55, p(4) >= 2221 && p(4) <= 2720: // Mastercard
		return n == 16
	case p(2) == 34 || p(2) == 37: // American Express
		return n == 15
	case p(4) == 6011, p(2) == 65, p(3) >= 644 && p(3) <= 649: // Discover
		return n >= 16 && n <= 19
	case p(2) == 36 || p(2) == 38, p(3) >= 300 && p(3) <= 305: // Diners Club
		return n >= 14 && n <= 19
	case p(4) >= 3528 && p(4) <= 3589: // JCB
		return n >= 16 && n <= 19
	}
	return false
}

// ---- phone ----

func phone() *Detector {
	return &Detector{
		ID:   "phone",
		Desc: "phone number in international format (+ and 8-15 digits); off by default",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`\+[1-9][0-9]{7,14}`),
		},
		Optional: true,
		Hints:    []string{"+"},
		Check: func(line []byte, start, end int) bool {
			if c, ok := byteAt(line, start-1); ok && isWordByte(c) {
				return false
			}
			c, ok := byteAt(line, end)
			return !ok || !isWordByte(c)
		},
	}
}

// ---- user names (opt-in) ----

// userName is what a login name looks like: starts with a letter or
// underscore, then letters, digits and . _ -  (no @: emails have their own detector).
const userName = `([A-Za-z_][A-Za-z0-9._-]{0,63})`

func username() *Detector {
	return &Detector{
		ID: "username",
		Desc: "login name after user=, username:, \"user\": ..., sshd/sudo messages (Accepted ... for NAME, Invalid user NAME, sudo: NAME : TTY); " +
			"role accounts such as root or runner are left alone; off by default",
		Optional: true,
		Patterns: []*regexp.Regexp{
			// user=alice, "username": "alice", login: alice; the key must end in the word.
			regexp.MustCompile(`(?i)\b(?:user(?:name)?|login|logname|uid)["']?\s*[:=]\s*["']?` + userName),
			// sshd: Accepted publickey for alice from ..., Failed password for invalid user bob from ...
			regexp.MustCompile(`(?i)\b(?:accepted|failed)\s+\S+\s+for\s+(?:(?:invalid|illegal)\s+user\s+)?` + userName + `\s+from\b`),
			// sshd: Invalid user bob from ...; PAM: session opened for user carol
			regexp.MustCompile(`(?i)\b(?:invalid|illegal)\s+user\s+` + userName),
			regexp.MustCompile(`(?i)\bsession\s+(?:opened|closed)\s+for\s+user\s+` + userName),
			// sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=...
			regexp.MustCompile(`(?i)\bsudo:\s+` + userName + `\s+:\s+(?:tty|pwd|user)=`),
		},
		Groups:    []int{1},
		Hints:     []string{"user", "login", "logname", "uid", "sudo", "accepted", "failed"},
		FoldHints: true,
		Pseudonym: true,
		Canonical: bytesToLower,
		Validate: func(name []byte) bool {
			l := strings.ToLower(string(name))
			return !homeSkip[l] && !userPlaceholder[l] && validKVValue(name)
		},
	}
}

// userPlaceholder lists values that stand for "no user", not a person.
var userPlaceholder = map[string]bool{
	"unknown": true, "anonymous": true, "anon": true, "system": true, "daemon": true, "service": true,
	"unauthenticated": true, "invalid": true, "empty": true, "na": true, "n": true, "id": true,
	"name": true, "username": true, "login": true, "uid": true, "string": true, "str": true, "me": true,
	"self": true, "current": true, "owner": true, "unspecified": true, "any": true,
}

// ---- host names (opt-in) ----

// hostTLDs are the top-level domains hostname recognises. It is a list, not
// "any two letters", because x.py, main.rs and foo.md are file names; the
// country codes that are also common file extensions (pl, sh, so, md, ...) are
// left out on purpose.
var hostTLDs = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range strings.Fields(`
		com net org edu gov mil int info biz name pro io dev app cloud online site tech xyz club shop store
		local localhost internal lan corp home intranet localdomain private
		eu de fr uk nl es it ch at be se dk fi ru cn jp kr in br au ca us tn ma dz eg za ng ke ie pt gr
		cz hu ro bg ua tr il ae sa mx ar cl co nz sg hk tw th vn id my ph
	`) {
		m[t] = true
	}
	return m
}()

func hostname() *Detector {
	label := `[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?`
	return &Detector{
		ID:       "hostname",
		Desc:     "fully qualified host name with a common top-level domain (db1.corp.example.com, build-7.internal); off by default",
		Optional: true,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?:` + label + `\.)+[A-Za-z]{2,24}`),
		},
		Hints:     []string{"."},
		Pseudonym: true,
		Canonical: bytesToLower,
		Validate: func(b []byte) bool {
			s := strings.ToLower(string(b))
			return len(s) <= 253 && hostTLDs[s[strings.LastIndexByte(s, '.')+1:]]
		},
		Check: func(line []byte, start, end int) bool {
			if c, ok := byteAt(line, start-1); ok && (isWordByte(c) || c == '.' || c == '-') {
				return false // the tail of a longer dotted name
			}
			c, ok := byteAt(line, end)
			if !ok {
				return true
			}
			if c == '.' { // a sentence-ending dot is fine; a.b.com.x is not a host
				n, ok := byteAt(line, end+1)
				return !ok || !isWordByte(n)
			}
			return !isWordByte(c) && c != '-' && c != '('
		},
	}
}

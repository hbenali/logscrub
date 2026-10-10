package detect

import (
	"math"
	"regexp"
	"strings"
)

// Provider-specific tokens. They all have a distinctive prefix, so they are
// precise (few false positives) and cheap (the prefix is the prefilter hint).

func prefixed(id, desc string, hints []string, patterns ...string) *Detector {
	d := &Detector{ID: id, Desc: desc, Hints: hints}
	for _, p := range patterns {
		d.Patterns = append(d.Patterns, regexp.MustCompile(p))
	}
	return d
}

func dockerHubToken() *Detector {
	return prefixed("dockerhub-token", "Docker Hub access token (dckr_pat_)",
		[]string{"dckr_pat_"}, `\bdckr_pat_[A-Za-z0-9_-]{20,}`)
}

func anthropicKey() *Detector {
	return prefixed("anthropic-key", "Anthropic API key (sk-ant-)",
		[]string{"sk-ant-"}, `\bsk-ant-[A-Za-z0-9_-]{32,}`)
}

func openAIKey() *Detector {
	return prefixed("openai-key", "OpenAI API key (sk-proj-, sk-svcacct-, sk-admin-, legacy sk-)",
		[]string{"sk-"}, `\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}`, `\bsk-[A-Za-z0-9]{48}\b`)
}

func googleAPIKey() *Detector {
	return prefixed("google-api-key", "Google API key (AIza...)",
		[]string{"AIza"}, `\bAIza[0-9A-Za-z_-]{35}\b`)
}

func npmToken() *Detector {
	return prefixed("npm-token", "npm access token (npm_)",
		[]string{"npm_"}, `\bnpm_[A-Za-z0-9]{36}\b`)
}

func pypiToken() *Detector {
	return prefixed("pypi-token", "PyPI upload token (pypi-)",
		[]string{"pypi-"}, `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`)
}

func sendgridKey() *Detector {
	return prefixed("sendgrid-key", "SendGrid API key (SG.)",
		[]string{"SG."}, `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`)
}

func huggingFaceToken() *Detector {
	return prefixed("huggingface-token", "Hugging Face access token (hf_)",
		[]string{"hf_"}, `\bhf_[A-Za-z0-9]{34,}\b`)
}

func shopifyToken() *Detector {
	return prefixed("shopify-token", "Shopify access token (shpat_, shpca_, shppa_, shpss_)",
		[]string{"shpat_", "shpca_", "shppa_", "shpss_"}, `\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b`)
}

func digitalOceanToken() *Detector {
	return prefixed("digitalocean-token", "DigitalOcean token (dop_v1_, doo_v1_, dor_v1_)",
		[]string{"_v1_"}, `\bdo[opr]_v1_[a-f0-9]{64}\b`)
}

func vaultToken() *Detector {
	return prefixed("vault-token", "HashiCorp Vault token (hvs.)",
		[]string{"hvs."}, `\bhvs\.[A-Za-z0-9_-]{24,}`)
}

func ageKey() *Detector {
	return prefixed("age-key", "age secret key (AGE-SECRET-KEY-1)",
		[]string{"AGE-SECRET-KEY-1"}, `\bAGE-SECRET-KEY-1[A-Z0-9]{58}\b`)
}

func telegramBotToken() *Detector {
	return prefixed("telegram-token", "Telegram bot token (123456789:AA...)",
		[]string{":AA"}, `\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b`)
}

func azureStorageKey() *Detector {
	d := prefixed("azure-storage-key", "Azure storage AccountKey= in a connection string",
		[]string{"accountkey"}, `(?i)\baccountkey=([A-Za-z0-9+/]{86}==)`)
	d.FoldHints = true
	d.Groups = []int{1}
	return d
}

// ---- cookies ----

func cookie() *Detector {
	d := prefixed("cookie", "value of a Cookie / Set-Cookie header or field (name=value pairs)",
		[]string{"cookie"}, `(?i)\b(?:set-)?cookie["']?\s*[:=]\s*["']?([^\s;"'=]+=[^\r\n"']+)`)
	d.FoldHints = true
	d.Groups = []int{1}
	return d
}

// ---- IBAN ----

// ibanLengths holds the fixed length per country for the common ones; other
// countries are accepted on the checksum alone.
var ibanLengths = map[string]int{
	"AT": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "EE": 20,
	"ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IS": 26,
	"IT": 27, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MT": 31, "NL": 18, "NO": 15,
	"PL": 28, "PT": 25, "RO": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TN": 24, "TR": 26,
	"MA": 28, "SA": 24, "AE": 23, "QA": 29, "KW": 30, "LB": 28, "JO": 30, "IL": 23, "BR": 29,
}

func iban() *Detector {
	d := &Detector{
		ID:   "iban",
		Desc: "IBAN bank account number (mod-97 checked)",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}`),
			regexp.MustCompile(`[A-Z]{2}[0-9]{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?`),
		},
		Pre:       hasUpperPair,
		Pseudonym: true,
		Canonical: func(b []byte) []byte {
			return []byte(strings.ToUpper(strings.ReplaceAll(string(b), " ", "")))
		},
		Validate: validIBAN,
		Check: func(line []byte, start, end int) bool {
			if c, ok := byteAt(line, start-1); ok && isWordByte(c) {
				return false
			}
			c, ok := byteAt(line, end)
			return !ok || !isWordByte(c)
		},
	}
	return d
}

// hasUpperPair is the IBAN prefilter: two capitals followed by two digits.
func hasUpperPair(line []byte) bool {
	for i := 0; i+3 < len(line); i++ {
		if line[i] >= 'A' && line[i] <= 'Z' && line[i+1] >= 'A' && line[i+1] <= 'Z' && isDigit(line[i+2]) && isDigit(line[i+3]) {
			return true
		}
	}
	return false
}

func validIBAN(b []byte) bool {
	s := strings.ReplaceAll(string(b), " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	if want, ok := ibanLengths[s[:2]]; ok && len(s) != want {
		return false
	}
	// Move the first four characters to the end, map letters to 10..35 and
	// check that the number is 1 modulo 97.
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, c := range []byte(rearranged) {
		switch {
		case isDigit(c):
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			rem = (rem*100 + int(c-'A') + 10) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// ---- home directories ----

// homeSkip lists usernames that name a role or an image, not a person.
var homeSkip = map[string]bool{
	"runner": true, "ubuntu": true, "user": true, "users": true, "root": true, "nobody": true, "node": true,
	"app": true, "build": true, "builder": true, "jenkins": true, "vagrant": true, "ec2-user": true,
	"azureuser": true, "admin": true, "default": true, "shared": true, "public": true, "guest": true,
	"circleci": true, "gitlab-runner": true, "git": true, "www-data": true, "docker": true, "test": true,
	"deploy": true, "all": true, "buildkite-agent": true, "runneradmin": true, "appuser": true,
}

func homePath() *Detector {
	return &Detector{
		ID:   "home-path",
		Desc: "user name in /home/NAME, /Users/NAME or C:\\Users\\NAME (role names such as runner are left alone)",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`/(?:home|Users)/([A-Za-z0-9._-]+)`),
			regexp.MustCompile(`(?i:[a-z]:\\+users\\+)([A-Za-z0-9._-]+)`),
		},
		Groups:    []int{1},
		Hints:     []string{"/home/", "/users/", "users\\"},
		FoldHints: true,
		Pseudonym: true,
		Canonical: bytesToLower,
		Validate: func(name []byte) bool {
			return !homeSkip[strings.ToLower(string(name))] && len(name) > 1
		},
	}
}

func bytesToLower(b []byte) []byte { return []byte(strings.ToLower(string(b))) }

// ---- opt-in detectors ----

func usSSN() *Detector {
	return &Detector{
		ID:       "us-ssn",
		Desc:     "US social security number (123-45-6789); off by default",
		Optional: true,
		Patterns: []*regexp.Regexp{regexp.MustCompile(`[0-9]{3}-[0-9]{2}-[0-9]{4}`)},
		Hints:    []string{"-"},
		Validate: func(b []byte) bool {
			area, group, serial := string(b[0:3]), string(b[4:6]), string(b[7:11])
			return area != "000" && area != "666" && area[0] != '9' && group != "00" && serial != "0000"
		},
		Check: func(line []byte, start, end int) bool {
			if c, ok := byteAt(line, start-1); ok && (isWordByte(c) || c == '-' || c == '.') {
				return false
			}
			c, ok := byteAt(line, end)
			return !ok || (!isWordByte(c) && c != '-')
		},
	}
}

func macAddress() *Detector {
	return &Detector{
		ID:       "mac-address",
		Desc:     "hardware (MAC) address; off by default",
		Optional: true,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}`),
			regexp.MustCompile(`[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}`),
		},
		Hints:     []string{":", "-"},
		Pseudonym: true,
		Canonical: func(b []byte) []byte {
			return []byte(strings.ToLower(strings.ReplaceAll(string(b), "-", ":")))
		},
		Check: func(line []byte, start, end int) bool {
			if c, ok := byteAt(line, start-1); ok && (isWordByte(c) || c == ':' || c == '-') {
				return false
			}
			c, ok := byteAt(line, end)
			return !ok || (!isWordByte(c) && c != ':' && c != '-')
		},
	}
}

// highEntropy finds unlabelled random-looking strings. It is the most
// false-positive-prone detector, so it is opt-in.
func highEntropy() *Detector {
	return &Detector{
		ID:   "high-entropy",
		Desc: "long random-looking string with no label (letters and digits, entropy > 4); off by default, expect false positives",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`[A-Za-z0-9+]{24,}={0,2}`),
			regexp.MustCompile(`[A-Za-z0-9_-]{24,}`),
		},
		Optional: true,
		Pre:      func(line []byte) bool { return len(line) >= 24 },
		Validate: validHighEntropy,
		Check: func(line []byte, start, end int) bool {
			// Not a path segment or a part of a longer dotted/slashed name.
			if c, ok := byteAt(line, start-1); ok && (c == '/' || c == '.' || isWordByte(c)) {
				return false
			}
			c, ok := byteAt(line, end)
			return !ok || (!isWordByte(c) && c != '/' && c != '.')
		},
	}
}

func validHighEntropy(b []byte) bool {
	var upper, lower, digit bool
	counts := map[byte]int{}
	hex := true
	for _, c := range b {
		counts[c]++
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case isDigit(c):
			digit = true
		}
		if c != '-' && !isDigit(c) && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			hex = false // hashes and UUIDs (hex with dashes) are not secrets
		}
	}
	if hex || !digit || (!upper && !lower) { // hashes, plain words, plain numbers
		return false
	}
	if !upper && (bytesContain(b, '-') || bytesContain(b, '_')) { // slugs and identifiers
		return false
	}
	return shannon(counts, len(b)) > 4.0 && countClasses(upper, lower, digit) >= 2
}

func bytesContain(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

func countClasses(flags ...bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

func shannon(counts map[byte]int, n int) float64 {
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * log2(p)
	}
	return h
}

func log2(x float64) float64 { return math.Log2(x) }

package traceevent

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var detailRedactors = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)\b(proxy[_-]?authorization|authorization)\s*[:=]\s*[^\r\n]+`), `${1}=[REDACTED]`},
	{regexp.MustCompile(`(?i)\b(pin|password|passwd)\s*[:=]\s*(?:"[^"]*"|'[^']*'|\S+)`), `${1}=[REDACTED]`},
	{regexp.MustCompile(`(?i)\b(payload[_-]?base64|ciphertext|dpapi)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[A-Za-z0-9+/=_-]+)`), `${1}=[REDACTED]`},
	{regexp.MustCompile(`(?i)://[^\s/:@]+:[^\s/@]+@`), `://[REDACTED]@`},
	{regexp.MustCompile(`(?i)\b(?:agent\.yaml|sing-box\.json)\b`), `[REDACTED_CONFIG]`},
}

func SanitizeDetail(value string, explicit ...[]byte) (detail string, truncated bool) {
	detail = value
	for _, secret := range explicit {
		if len(secret) != 0 {
			detail = strings.ReplaceAll(detail, string(secret), "[REDACTED]")
		}
	}
	for _, redactor := range detailRedactors {
		detail = redactor.pattern.ReplaceAllString(detail, redactor.replacement)
	}
	detail = strings.Map(func(value rune) rune {
		if unicode.IsControl(value) {
			return ' '
		}
		return value
	}, detail)
	detail = strings.Join(strings.Fields(detail), " ")
	if len([]byte(detail)) <= MaxDetailBytes {
		return detail, false
	}
	bytes := []byte(detail)
	bytes = bytes[:MaxDetailBytes]
	for len(bytes) > 0 && !utf8.Valid(bytes) {
		bytes = bytes[:len(bytes)-1]
	}
	return string(bytes), true
}

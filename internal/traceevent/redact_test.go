package traceevent

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeDetailRedactsForbiddenMaterial(t *testing.T) {
	secret := []byte("Syy99518@")
	input := strings.Join([]string{
		"pin=234567",
		"password: Sup3rSecret!",
		"proxy_authorization=Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
		"https://admin:secret@example.invalid/path",
		"agent.yaml sing-box.json",
		"payload_base64=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
		"explicit=" + string(secret),
	}, "\n")
	detail, truncated := SanitizeDetail(input, secret)
	if truncated {
		t.Fatal("short detail was truncated")
	}
	for _, forbidden := range []string{
		"234567", "Sup3rSecret", "QWxhZGRpb", "admin:secret", "agent.yaml",
		"sing-box.json", "QUJDREVGR0hJ", string(secret),
	} {
		if strings.Contains(detail, forbidden) {
			t.Fatalf("detail contains forbidden %q: %q", forbidden, detail)
		}
	}
	if !strings.Contains(detail, "[REDACTED]") {
		t.Fatalf("detail has no redaction marker: %q", detail)
	}
}

func TestSanitizeDetailNormalizesControlCharacters(t *testing.T) {
	detail, _ := SanitizeDetail("first\x00\x01\r\nsecond\tvalue")
	if strings.ContainsAny(detail, "\x00\x01\r\n\t") {
		t.Fatalf("control characters remain: %q", detail)
	}
	if detail != "first second value" {
		t.Fatalf("detail = %q", detail)
	}
}

func TestSanitizeDetailTruncatesAtUTF8Boundary(t *testing.T) {
	detail, truncated := SanitizeDetail(strings.Repeat("界", 2000))
	if !truncated {
		t.Fatal("detail was not marked truncated")
	}
	if len([]byte(detail)) > MaxDetailBytes || !utf8.ValidString(detail) {
		t.Fatalf("detail bytes=%d valid=%v", len([]byte(detail)), utf8.ValidString(detail))
	}
}

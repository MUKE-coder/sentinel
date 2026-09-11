package detection

import "strings"

// maxDecodeLayers bounds how many further rounds of percent-decoding the
// classifier applies to a value. The router and url.ParseQuery decode once;
// anything still encoded after that was encoded twice on purpose — "%2527"
// is an apostrophe to an app that decodes again, and invisible to a WAF that
// stops at one layer.
const maxDecodeLayers = 2

// decodedLayers returns s after each further round of percent-decoding that
// changes it, at most maxDecodeLayers. Decoding is lenient: a "%" that isn't
// an escape is kept as-is instead of failing the whole value, so appending
// "100%" to a payload can't switch decoding off.
func decodedLayers(s string, plusAsSpace bool) []string {
	var layers []string
	for i := 0; i < maxDecodeLayers; i++ {
		next, ok := percentDecode(s, plusAsSpace)
		if !ok {
			break
		}
		layers = append(layers, next)
		s = next
	}
	return layers
}

// percentDecode decodes every valid %XX escape in s, and "+" to a space when
// plusAsSpace is set (form and query encoding). ok is false when s holds no
// escape to decode.
func percentDecode(s string, plusAsSpace bool) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	decoded := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			decoded = true
		case c == '+' && plusAsSpace:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), decoded
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

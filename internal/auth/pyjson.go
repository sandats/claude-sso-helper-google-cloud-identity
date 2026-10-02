package auth

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// PyJSON renders a scalar like Python's json.dumps (ensure_ascii=True), keeping
// cache keys and printed output byte-compatible with the Python helper.
func PyJSON(v any) string { return pyJSON(v) }

func pyJSON(v any) string {
	switch v := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(v)
	case string:
		return pyJSONString(v)
	case json.Number:
		return v.String()
	case int:
		return strconv.Itoa(v)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return "null"
		}
		return string(raw)
	}
}

func pyJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			switch {
			case r >= ' ' && r <= '~':
				b.WriteRune(r)
			case r < 0x10000:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

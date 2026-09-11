package detection

import (
	"reflect"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

func TestDecodedLayers(t *testing.T) {
	cases := []struct {
		in    string
		plus  bool
		want  []string
		about string
	}{
		{"plain", true, nil, "nothing encoded"},
		{"100% cotton", true, nil, "a stray % is not an escape"},
		{"%2527", true, []string{"%27", "'"}, "double-encoded apostrophe"},
		{"%252527", true, []string{"%2527", "%27"}, "stops after maxDecodeLayers"},
		{"1%27 OR 100%", true, []string{"1' OR 100%"}, "a stray % does not switch decoding off"},
		{"a+b%21", true, []string{"a b!"}, "plus is a space in form encoding"},
		{"a+b%21", false, []string{"a+b!"}, "plus is literal in a path"},
		{"%3c%3E", true, []string{"<>"}, "hex digits in either case"},
		{"%4", true, nil, "truncated escape"},
	}
	for _, tc := range cases {
		if got := decodedLayers(tc.in, tc.plus); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: decodedLayers(%q) = %q, want %q", tc.about, tc.in, got, tc.want)
		}
	}
}

// A payload encoded one more time than the router decodes must still be
// classified: the application may decode it again.
func TestClassifyRequestDecodesLeftoverEncoding(t *testing.T) {
	cases := []struct {
		name string
		req  sentinel.InspectedRequest
		want sentinel.ThreatType
	}{
		{"double-encoded query", sentinel.InspectedRequest{RawQuery: "id=1%2527%20OR%20%25271%2527%3D%25271"}, sentinel.ThreatSQLi},
		{"double-encoded query with stray %", sentinel.InspectedRequest{RawQuery: "id=1%2527%20OR%20%25271%2527%3D%25271%20100%25"}, sentinel.ThreatSQLi},
		{"form-encoded body", sentinel.InspectedRequest{Body: "username=admin%27+OR+%271%27%3D%271&password=x"}, sentinel.ThreatSQLi},
		{"encoded path", sentinel.InspectedRequest{Path: "/download/%2E%2E%2Fetc%2Fpasswd"}, sentinel.ThreatPathTraversal},
		{"encoded query key", sentinel.InspectedRequest{RawQuery: "a%5B__proto__%5D%5Bx%5D=1"}, sentinel.ThreatPrototypePollution},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, m := range ClassifyRequest(tc.req) {
				if m.ThreatType == tc.want {
					return
				}
			}
			t.Errorf("expected %s, got %v", tc.want, matchTypes(ClassifyRequest(tc.req)))
		})
	}
}

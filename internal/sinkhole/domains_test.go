package sinkhole

import (
	"strings"
	"testing"
)

func TestDomains(t *testing.T) {
	const input = `# comment
Ads.Example. # inline
0.0.0.0 track.example other.example
::1 localhost ip6-localhost
`
	domains, err := ParseDomains(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 3 {
		t.Fatalf("got %d entries", len(domains))
	}
	for _, name := range []string{"ads.example.", "SUB.ADS.EXAMPLE.", "track.example", "other.example"} {
		if !domains.Matches(name) {
			t.Errorf("did not match %s", name)
		}
	}
	for _, name := range []string{"badads.example", "example", "localhost", "ads.example.evil"} {
		if domains.Matches(name) {
			t.Errorf("unexpected match %s", name)
		}
	}
}

func TestInvalidDomains(t *testing.T) {
	for _, input := range []string{"https://ads.example", "*.example", "ads.example garbage", "a..example", "-a.example", "0.0.0.0 https://example"} {
		if _, err := ParseDomains(strings.NewReader(input)); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

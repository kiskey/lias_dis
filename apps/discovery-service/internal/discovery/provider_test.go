package discovery

import "testing"

func TestUnescapeHostnameUsesThreeDigitDecimalEscapes(t *testing.T) {
	if got := UnescapeHostname(`Living\032Room\.local`); got != "Living Room.local" {
		t.Fatalf("unexpected hostname unescape: %q", got)
	}
}

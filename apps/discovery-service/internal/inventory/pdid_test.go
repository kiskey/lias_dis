package inventory

import "testing"

func TestPermanentIdentityIsOpaqueAndUnique(t *testing.T) {
	d1, p1, err := NewPermanentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	d2, p2, err := NewPermanentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 || p1 == p2 {
		t.Fatal("random identity collision")
	}
	if len(d1) != 36 || len(p1) != 37 {
		t.Fatalf("unexpected ID lengths: %q %q", d1, p1)
	}
}

func TestLocallyAdministeredBitIsNotRandomizationProof(t *testing.T) {
	if !IsLocallyAdministeredMAC("02:00:00:00:00:01") {
		t.Fatal("U/L bit not detected")
	}
	if IsLocallyAdministeredMAC("00:00:00:00:00:01") {
		t.Fatal("global MAC marked local")
	}
}

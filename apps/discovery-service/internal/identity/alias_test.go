package identity

import (
	"testing"

	"github.com/user/lias-dis/shared/models"
)

func TestAliasHashCanonicalizationAndSeparation(t *testing.T) {
	a, err := HashAlias(models.AliasMAC, "02-AA-BB-CC-DD-EE")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashAlias(models.AliasMAC, "02:aa:bb:cc:dd:ee")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("equivalent MACs produced different hashes")
	}
	c, err := HashAlias(models.AliasManual, "02:aa:bb:cc:dd:ee")
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("alias type was not domain-separated")
	}
}

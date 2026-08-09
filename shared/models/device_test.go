package models

import "testing"

func TestDeviceCloneDoesNotShareMutableState(t *testing.T) {
	original := &Device{
		MACs:     []string{"aa:bb:cc:dd:ee:ff"},
		Services: []string{"_airplay._tcp"},
		SourceInfo: map[string]SourceMeta{
			"mdns": {Raw: map[string]interface{}{"txt": []interface{}{"one"}}},
		},
	}
	clone := original.Clone()
	clone.MACs[0] = "00:00:00:00:00:00"
	clone.Services[0] = "changed"
	clone.SourceInfo["mdns"].Raw["txt"].([]interface{})[0] = "two"

	if original.MACs[0] != "aa:bb:cc:dd:ee:ff" || original.Services[0] != "_airplay._tcp" {
		t.Fatal("clone mutated original slices")
	}
	if original.SourceInfo["mdns"].Raw["txt"].([]interface{})[0] != "one" {
		t.Fatal("clone mutated original source metadata")
	}
}

//go:build darwin

package main

import "testing"

func TestLocalUIDSearchRejectsAmbiguousOrWrongMapping(t *testing.T) {
	for _, text := range []string{"", "root 0", "daily 709\nother 709", "daily 710", "daily 709 extra", "../escape 709"} {
		if _, err := localNameForUID([]byte(text), 709); err == nil {
			t.Fatal(text)
		}
	}
	if got, err := localNameForUID([]byte("daily\t\t709\n"), 709); err != nil || got != "daily" {
		t.Fatal(got, err)
	}
}

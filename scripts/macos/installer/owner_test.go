package main

import (
	"errors"
	"testing"
)

func TestSelectInstallOwnerPreservesReceiptIdentity(t *testing.T) {
	daily := account{"daily", 709, "/Users/daily"}
	lookup := func(uid int) (account, error) {
		if uid == 709 {
			return daily, nil
		}
		return account{}, errors.New("not local")
	}
	existing := &receipt{Version: 1, OwnerUID: 709, CASHA256: caDigest}
	got, err := selectInstallOwner(existing, account{"different", 501, "/Users/different"}, lookup)
	if err != nil || got != daily {
		t.Fatal(got, err)
	}
	existing.OwnerUID = 710
	if _, err := selectInstallOwner(existing, daily, lookup); err == nil {
		t.Fatal("missing previous owner silently replaced")
	}
	existing.OwnerUID = 709
	existing.CASHA256 = "foreign"
	if _, err := selectInstallOwner(existing, daily, lookup); err == nil {
		t.Fatal("invalid receipt accepted")
	}
}

func TestSelectInstallOwnerRejectsSystemAndMismatchedIdentity(t *testing.T) {
	for _, a := range []account{{}, {"root", 0, "/var/root"}, {"loginwindow", 501, "/Users/loginwindow"}, {"_daemon", 501, "/Users/_daemon"}} {
		if _, err := selectInstallOwner(nil, a, func(int) (account, error) { return a, nil }); err == nil {
			t.Fatal(a)
		}
	}
	daily := account{"daily", 709, "/Users/daily"}
	wrong := account{"other", 709, "/Users/other"}
	if _, err := selectInstallOwner(nil, daily, func(int) (account, error) { return wrong, nil }); err == nil {
		t.Fatal("console name mismatch accepted")
	}
	if got, err := selectInstallOwner(nil, daily, func(int) (account, error) { return daily, nil }); err != nil || got != daily {
		t.Fatal(got, err)
	}
}

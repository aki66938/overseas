package main

import "errors"

// Account resolution is supplied by the local directory adapter, never SSH/sudo identity.
func selectInstallOwner(existing *receipt, console account, lookup func(int) (account, error)) (account, error) {
	uid := console.UID
	if existing != nil {
		if existing.Version != 1 || existing.CASHA256 != caDigest || existing.OwnerUID < 501 {
			return account{}, errors.New("invalid owner receipt")
		}
		uid = existing.OwnerUID
	} else if err := validateAccount(console); err != nil || console.Name == "loginwindow" {
		return account{}, errors.New("a real local graphical user is required")
	}
	resolved, err := lookup(uid)
	if err != nil {
		return account{}, err
	}
	if err = validateAccount(resolved); err != nil {
		return account{}, err
	}
	if resolved.UID != uid || resolved.Name == "loginwindow" || (existing == nil && resolved != console) {
		return account{}, errors.New("local owner identity mismatch")
	}
	return resolved, nil
}

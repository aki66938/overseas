//go:build darwin

package main

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func localNameForUID(data []byte, uid int) (string, error) {
	fields := strings.Fields(string(data))
	if uid < 501 || len(fields) != 2 || fields[1] != strconv.Itoa(uid) || !safeName(fields[0]) || strings.Contains(fields[0], "/") {
		return "", errors.New("local UID does not uniquely map to an ordinary account")
	}
	return fields[0], nil
}

func lookupLocalUID(uid int) (account, error) {
	if uid < 501 {
		return account{}, errors.New("system UID is not an installation owner")
	}
	out, err := command("/usr/bin/dscl", ".", "-search", "/Users", "UniqueID", strconv.Itoa(uid))
	if err != nil {
		return account{}, err
	}
	name, err := localNameForUID(out, uid)
	if err != nil {
		return account{}, err
	}
	a, err := lookupOwner(name)
	if err != nil {
		return account{}, err
	}
	var home unix.Stat_t
	if err = unix.Lstat(a.Home, &home); err != nil {
		return account{}, err
	}
	if a.UID != uid || home.Uid != uint32(uid) || home.Mode&unix.S_IFMT != unix.S_IFDIR {
		return account{}, errors.New("local user/home ownership mismatch")
	}
	return a, nil
}

func installOwner(old bool, requested string) (account, error) {
	var console unix.Stat_t
	if err := unix.Stat("/dev/console", &console); err != nil {
		return account{}, err
	}
	current, err := lookupLocalUID(int(console.Uid))
	if err != nil {
		return account{}, err
	}
	var existing *receipt
	if old {
		data, err := os.ReadFile(installRoot + "/receipt.json")
		if err != nil {
			return account{}, err
		}
		existing = &receipt{}
		if err = strictJSON(data, existing); err != nil {
			return account{}, err
		}
	}
	a, err := selectInstallOwner(existing, current, lookupLocalUID)
	if err != nil {
		return account{}, err
	}
	if requested != "" && requested != a.Name {
		return account{}, errors.New("requested owner differs from graphical user or installed owner")
	}
	return a, nil
}

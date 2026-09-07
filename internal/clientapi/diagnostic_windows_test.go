//go:build windows

package clientapi

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestDefaultAdministratorDialOffersIdentificationToken(t *testing.T) {
	path := fmt.Sprintf(`\\.\pipe\regen-admin-client-test-%s`, rand.Text())
	listener, err := winio.ListenPipe(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := bufio.NewReader(connection).ReadBytes('\n'); err != nil {
			result <- err
			return
		}
		runtime.LockOSThread()
		proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
		r, _, err := proc.Call(connection.(interface{ Fd() uintptr }).Fd())
		if r == 0 {
			runtime.UnlockOSThread()
			result <- err
			return
		}
		var token windows.Token
		err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		if err == nil {
			err = token.Close()
		}
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			result <- revertErr
			return
		}
		runtime.UnlockOSThread()
		result <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := defaultDialAdminPipe(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte("identification\n")); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("administrator dial did not expose queryable peer token: %v", err)
	}
}

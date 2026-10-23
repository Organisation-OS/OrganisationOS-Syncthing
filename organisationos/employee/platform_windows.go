//go:build windows

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func hide(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
func platformReparse(path string) bool {
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return true
	}
	attributes, e := syscall.GetFileAttributes(p)
	return e != nil || attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
func devInstallLock(instance string) (func(), error) {
	return runLock(Config{Instance: instance + "-dev-install"})
}
func browser(u string) error {
	c := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", u)
	hide(c)
	return c.Start()
}
func notify(title, message string) {
	dll := syscall.NewLazyDLL("user32.dll")
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(message)
	dll.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
}
func runLock(c Config) (func(), error) {
	dll := syscall.NewLazyDLL("kernel32.dll")
	name, _ := syscall.UTF16PtrFromString(`Local\OrganisationOS-Syncthing-` + digest([]byte(base()+c.Instance)))
	handle, _, e := dll.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return nil, e
	}
	if e == syscall.Errno(183) {
		dll.NewProc("CloseHandle").Call(handle)
		return nil, errRunning
	}
	return func() { dll.NewProc("CloseHandle").Call(handle) }, nil
}
func registry(args ...string) error { c := exec.Command("reg.exe", args...); hide(c); return c.Run() }
func psQuote(s string) string       { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func register(exe string, c Config) error {
	root := `HKCU\Software\Classes\organisationos-syncthing`
	query := exec.Command("reg.exe", "query", root)
	hide(query)
	if query.Run() == nil {
		q := exec.Command("reg.exe", "query", root, "/v", "OrganisationOSOwner")
		hide(q)
		b, e := q.Output()
		if e != nil || !strings.Contains(string(b), "employee-v1") {
			return errors.New("existing protocol owner differs")
		}
	}
	for _, args := range [][]string{{"add", root, "/v", "OrganisationOSOwner", "/t", "REG_SZ", "/d", "employee-v1", "/f"}, {"add", root, "/ve", "/t", "REG_SZ", "/d", "URL:OrganisationOS Syncthing", "/f"}, {"add", root, "/v", "URL Protocol", "/t", "REG_SZ", "/d", "", "/f"}, {"add", root + `\shell\open\command`, "/ve", "/t", "REG_SZ", "/d", `"` + exe + `" "%1"`, "/f"}, {"add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "OrganisationOS-Syncthing-" + c.Instance, "/t", "REG_SZ", "/d", `"` + exe + `" run ` + c.Instance, "/f"}} {
		if e := registry(args...); e != nil {
			return e
		}
	}
	menu := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "OrganisationOS")
	if e := os.MkdirAll(menu, 0700); e != nil {
		return e
	}
	shortcut := filepath.Join(menu, "Syncthing - "+c.Instance+".lnk")
	script := "$ErrorActionPreference='Stop'; $w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut(" + psQuote(shortcut) + "); $s.TargetPath=" + psQuote(exe) + "; $s.Arguments=" + psQuote("connect "+c.Instance) + "; $s.Description=" + psQuote("Syncthing OrganisationOS — "+c.Name) + "; $s.Save()"
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	hide(command)
	return command.Run()
}

//go:build linux

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"errors"
	"os/exec"
)

func hide(*exec.Cmd)                        {}
func platformReparse(string) bool           { return false }
func devInstallLock(string) (func(), error) { return nil, errors.New("Windows DEV installation only") }
func browser(string) error                  { return errors.New("Windows employee installer only") }
func notify(string, string)                 {}
func runLock(Config) (func(), error) {
	return nil, errors.New("Windows lifecycle not qualified on Linux")
}
func register(string, Config) error { return errors.New("Windows registry not available") }

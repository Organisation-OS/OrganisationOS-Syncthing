// SPDX-License-Identifier: MPL-2.0
package main

import (
	"os"
	"testing"
)

// Diagnostics are tested with synthetic transports. They must not leave a
// native modal Windows window waiting for a person during an automated suite.
func TestMain(m *testing.M) {
	showNotification = func(string, string) {}
	os.Exit(m.Run())
}

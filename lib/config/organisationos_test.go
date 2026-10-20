// Copyright (C) 2026 OrganisationOS contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
package config

import (
	"github.com/syncthing/syncthing/lib/protocol"
	"testing"
)

func TestOrganisationOSPrivateDefaults(t *testing.T) {
	cfg := New(protocol.LocalDeviceID)
	o := cfg.Options
	if o.GlobalAnnEnabled || o.LocalAnnEnabled || o.RelaysEnabled || o.NATEnabled || o.CREnabled || o.URAccepted != -1 || o.AutoUpgradeEnabled() {
		t.Fatal("unexpected public service or upgrade default")
	}
	if len(o.RawListenAddresses) != 1 || o.RawListenAddresses[0] != "tcp://127.0.0.1:22000" {
		t.Fatal("unexpected listening address")
	}
	if err := cfg.ProbeFreePorts(); err != nil {
		t.Fatal(err)
	}
	if cfg.Options.RawListenAddresses[0] != "tcp://127.0.0.1:22000" {
		t.Fatal("port probing changed managed address")
	}
}

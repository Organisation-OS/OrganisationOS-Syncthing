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

func TestOrganisationOSLocalEncryptionCannotHideIdentity(t *testing.T) {
	local := protocol.NewDeviceID([]byte("synthetic-local"))
	remote := protocol.NewDeviceID([]byte("synthetic-remote"))
	for _, kind := range []FolderType{FolderTypeSendReceive, FolderTypeSendOnly, FolderTypeReceiveOnly, FolderTypeReceiveEncrypted} {
		cfg := New(local)
		cfg.Devices = append(cfg.Devices, DeviceConfiguration{DeviceID: remote, Untrusted: true})
		cfg.Folders = []FolderConfiguration{{ID: "synthetic", Path: t.TempDir(), Type: kind, Devices: []FolderDeviceConfiguration{
			{DeviceID: local, EncryptionPassword: "synthetic-invalid-local"},
			{DeviceID: remote, EncryptionPassword: "synthetic-valid-remote"},
		}}}
		if err := cfg.prepare(local); err != nil {
			t.Fatal(err)
		}
		if len(cfg.Folders[0].Devices) != 2 {
			t.Fatal("local and remote identities must remain registered")
		}
		for _, device := range cfg.Folders[0].Devices {
			if device.DeviceID == local && device.EncryptionPassword != "" {
				t.Fatal("local entry must never carry a recipient password")
			}
			if device.DeviceID == remote && device.EncryptionPassword != "synthetic-valid-remote" {
				t.Fatal("remote encryption must remain unchanged")
			}
		}
		if err := cfg.prepare(local); err != nil {
			t.Fatal(err)
		}
		if len(cfg.Folders[0].Devices) != 2 {
			t.Fatal("normalization must remain idempotent")
		}
	}
}

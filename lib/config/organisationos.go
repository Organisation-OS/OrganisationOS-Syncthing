// Copyright (C) 2026 OrganisationOS contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
package config

// New installations start without public discovery, relays, NAT or reporting.
// Existing configurations are preserved. These defaults are not GED authorization:
// only the OrganisationOS server projection decides which bytes are exposed.
func (cfg *Configuration) organisationOSDefaults() {
	cfg.Options.GlobalAnnEnabled = false
	cfg.Options.LocalAnnEnabled = false
	cfg.Options.RelaysEnabled = false
	cfg.Options.NATEnabled = false
	cfg.Options.CREnabled = false
	cfg.Options.URAccepted = -1
	cfg.Options.AutoUpgradeIntervalH = 0
	cfg.Options.RawListenAddresses = []string{"tcp://127.0.0.1:22000"}
}

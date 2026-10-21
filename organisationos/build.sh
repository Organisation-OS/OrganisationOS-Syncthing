#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
cd /work
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/work
mkdir -p organisationos-output organisationos-evidence
exec > >(tee organisationos-evidence/build.log) 2>&1
trap 's=$?; echo "$s" > organisationos-evidence/exit-status; exit "$s"' EXIT
export BUILD_USER=OrganisationOS BUILD_HOST=DEV SOURCE_DATE_EPOCH=1791244800
export GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2 CGO_ENABLED=1
git -c safe.directory=/work rev-parse HEAD > organisationos-evidence/source-commit.txt
go version > organisationos-evidence/go-version.txt
dpkg-query -W > organisationos-evidence/compiler-packages.tsv
go mod download
go mod verify
go list -m -json all > organisationos-evidence/go-modules.json
go test -short ./lib/config ./lib/build ./lib/protocol ./lib/scanner ./lib/fs ./lib/model
for pass in a b; do
  mkdir -p "organisationos-output/$pass"
  go run build.go -no-upgrade -version v2.1.6-oos.2 -goos linux -goarch amd64 -build-out "organisationos-output/$pass/organisationos-syncthing" build
  go run build.go -no-upgrade -version v2.1.6-oos.2 -goos windows -goarch amd64 -cc x86_64-w64-mingw32-gcc-posix -build-out "organisationos-output/$pass/organisationos-syncthing.exe" build
  go clean -cache
 done
cmp organisationos-output/a/organisationos-syncthing organisationos-output/b/organisationos-syncthing
cmp organisationos-output/a/organisationos-syncthing.exe organisationos-output/b/organisationos-syncthing.exe
sha256sum organisationos-output/a/* > organisationos-evidence/binary-sha256.txt
organisationos-output/a/organisationos-syncthing --version > organisationos-evidence/runtime-version.txt

# SPDX-License-Identifier: MPL-2.0
# Portable qualification only. No service, startup registration or existing client changes.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][switch]$Qualification)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $Qualification) { throw 'Le mode Qualification doit être explicite.' }
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Windows x64 est requis.' }
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'provenance.json') -Raw | ConvertFrom-Json
$source = Join-Path $PSScriptRoot 'organisationos-syncthing.exe'
$actual = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -cne $manifest.binary.sha256) { throw 'Empreinte du moteur invalide.' }
$base = Join-Path $env:LOCALAPPDATA 'OrganisationOS'
$target = Join-Path $base 'Syncthing-Qualification'
if (Test-Path -LiteralPath $target) { throw "Le répertoire existe déjà : $target. Arrêtez et examinez l'essai existant avant toute nouvelle installation." }
New-Item -ItemType Directory -Path $target | Out-Null
$state = Join-Path $target 'Etat'
$synthetic = Join-Path $target 'Fichiers-synthetiques'
New-Item -ItemType Directory -Path $state,$synthetic | Out-Null
Copy-Item -LiteralPath $source -Destination $target
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'provenance.json') -Destination $target
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE.txt'),(Join-Path $PSScriptRoot 'AUTHORS.txt'),(Join-Path $PSScriptRoot 'LIRE-MOI.txt') -Destination $target
$binary = Join-Path $target 'organisationos-syncthing.exe'
& $binary generate --home $state --no-port-probing
if ($LASTEXITCODE -ne 0) { throw 'Génération locale non terminée. Aucun moteur démarré.' }
function Get-LoopbackPort {
  $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
  $listener.Start()
  try { return $listener.LocalEndpoint.Port } finally { $listener.Stop() }
}
$gui = Get-LoopbackPort
$listen = Get-LoopbackPort
while ($listen -eq $gui) { $listen = Get-LoopbackPort }
$configPath = Join-Path $state 'config.xml'
$xml = New-Object System.Xml.XmlDocument
$xml.XmlResolver = $null
$xml.Load($configPath)
foreach ($folder in @($xml.SelectNodes('/configuration/folder'))) { [void]$folder.ParentNode.RemoveChild($folder) }
$xml.SelectSingleNode('/configuration/gui/address').InnerText = "127.0.0.1:$gui"
$xml.SelectSingleNode('/configuration/options/listenAddress').InnerText = "tcp://127.0.0.1:$listen"
foreach ($name in @('globalAnnounceEnabled','localAnnounceEnabled','relaysEnabled','natEnabled','crashReportingEnabled')) {
  if ($xml.SelectSingleNode("/configuration/options/$name").InnerText -cne 'false') { throw "Valeur privée attendue absente : $name" }
}
$xml.Save($configPath)
[IO.File]::WriteAllText((Join-Path $synthetic 'qualification.txt'), "Fichier synthetique OrganisationOS. Aucun document personnel.`r`n")
$launch = '@echo off' + "`r`n" + 'cd /d "%~dp0"' + "`r`n" + 'organisationos-syncthing.exe serve --home "%~dp0Etat" --no-browser --no-restart --no-upgrade --no-port-probing' + "`r`n" + 'pause' + "`r`n"
[IO.File]::WriteAllText((Join-Path $target 'Demarrer.cmd'), $launch, [Text.Encoding]::ASCII)
$device = $xml.SelectSingleNode('/configuration/device').GetAttribute('id')
Write-Host "Installation portable de qualification : $target"
Write-Host "Demarrage manuel : $target\Demarrer.cmd"
Write-Host "Interface locale apres demarrage : http://127.0.0.1:$gui"
Write-Host "Identifiant public du nouvel appareil : $device"
Write-Host "Seul dossier prevu pour les essais : $synthetic"
Write-Host 'Aucun service ni demarrage automatique ajoute. Aucune connexion GED configuree.'

# SPDX-License-Identifier: MPL-2.0
# Qualification upgrade only. No service, startup, pairing or personal files touched.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][switch]$Qualification)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $Qualification -or -not [Environment]::Is64BitOperatingSystem) { throw 'Qualification Windows x64 requise.' }
$b = Join-Path $env:LOCALAPPDATA 'OrganisationOS\Syncthing-Qualification'
$m = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'provenance.json') -Raw | ConvertFrom-Json
$src = Join-Path $PSScriptRoot 'organisationos-syncthing.exe'
$exe = Join-Path $b 'organisationos-syncthing.exe'
$newHash = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant()
if ($newHash -cne $m.binary.sha256 -or $m.packageVersion -cne '0.2.0-qualification') { throw 'Paquet inattendu.' }
if (-not (Test-Path -LiteralPath $exe)) { throw 'Installation existante absente.' }
if (@(Get-Process -Name 'organisationos-syncthing' -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $exe }).Count -ne 0) { throw 'Arretez le moteur de qualification avant la mise a jour.' }
$oldHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($oldHash -notin @('2a07186aab4f0e2b331760a6c4f7d743410548c58b6693e1cd7cb580d084a2d5',$newHash)) { throw 'Ancien moteur inconnu : aucun changement.' }
$preserved = @{}
foreach ($name in @('cert.pem','key.pem','config.xml')) {
 $p = Join-Path (Join-Path $b 'Etat') $name
 $preserved[$name] = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
}
$backup = Join-Path $b ('Sauvegarde-moteur-' + $oldHash)
if ($oldHash -cne $newHash) {
 if (Test-Path -LiteralPath $backup) { throw 'Sauvegarde deja presente : examiner une reprise avant modification.' }
 New-Item -ItemType Directory -Path $backup | Out-Null
 foreach ($name in @('provenance.json','LICENSE.txt','AUTHORS.txt','LIRE-MOI.txt')) {
  Copy-Item -LiteralPath (Join-Path $b $name) -Destination $backup
 }
 $staged = Join-Path $b ('moteur-' + [Guid]::NewGuid().ToString('N') + '.tmp')
 Copy-Item -LiteralPath $src -Destination $staged
 if ((Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash.ToLowerInvariant() -cne $newHash) { throw 'Copie invalide; moteur original conserve.' }
 [IO.File]::Replace($staged,$exe,(Join-Path $backup 'organisationos-syncthing.exe'))
}
foreach ($name in @('provenance.json','LICENSE.txt','AUTHORS.txt','LIRE-MOI.txt')) {
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $b $name) -Force
}
foreach ($name in $preserved.Keys) {
 if ((Get-FileHash -LiteralPath (Join-Path (Join-Path $b 'Etat') $name) -Algorithm SHA256).Hash -cne $preserved[$name]) { throw 'Etat modifie de facon concurrente; ne pas demarrer.' }
}
[pscustomobject]@{ MoteurSHA256 = $newHash; IdentiteEtConfigurationConservees = $true; FichiersNonModifiesParInstallateur = $true; MoteurDemarre = $false } | ConvertTo-Json

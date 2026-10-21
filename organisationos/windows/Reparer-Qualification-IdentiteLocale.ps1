# SPDX-License-Identifier: MPL-2.0
# Targeted repair through the local native API; preserves device certificates, files and remote encryption.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ExpectedDeviceId,[switch]$Repair)
$ErrorActionPreference = 'Stop'
$base = Join-Path $env:LOCALAPPDATA 'OrganisationOS\Syncthing-Qualification'
$configPath = Join-Path $base 'Etat\config.xml'
[xml]$xml = Get-Content -LiteralPath $configPath
$address = [string]$xml.configuration.gui.address
if ($address -notmatch '^127\.0\.0\.1:[0-9]{1,5}$') { throw 'Interface locale inattendue.' }
$headers = @{ 'X-API-Key' = [string]$xml.configuration.gui.apikey }
$url = 'http://' + $address + '/rest'
$folderId = 'oos-windows-synthetic-20261020'
try {
    $status = Invoke-RestMethod "$url/system/status" -Headers $headers
    if ($status.myID -cne $ExpectedDeviceId) { throw 'Identite active inattendue.' }
    $config = Invoke-RestMethod "$url/config" -Headers $headers
    $folders = @($config.folders | Where-Object { $_.id -ceq $folderId })
    if ($folders.Count -ne 1) { throw 'Dossier de qualification introuvable ou ambigu.' }
    $folder = $folders[0]
    $expectedPath = [IO.Path]::GetFullPath((Join-Path $base 'Fichiers-synthetiques')).TrimEnd('\')
    if ($folder.type -cne 'sendreceive' -or [IO.Path]::GetFullPath($folder.path).TrimEnd('\') -ine $expectedPath) { throw 'Perimetre du dossier inattendu.' }
    $self = @($folder.devices | Where-Object { $_.deviceID -ceq $ExpectedDeviceId })
    $selfConfig = @($config.devices | Where-Object { $_.deviceID -ceq $ExpectedDeviceId })
    if ($self.Count -ne 1 -or $selfConfig.Count -ne 1 -or $selfConfig[0].untrusted) { throw 'Entree locale inattendue.' }
    $present = -not [string]::IsNullOrEmpty([string]$self[0].encryptionPassword)
    if (-not $Repair) { [pscustomobject]@{ Mode='Lecture seule'; Identite=$status.myID; ChiffrementLocalRenseigne=$present }; return }
    if (-not $present) { [pscustomobject]@{ Statut='DEJA_CORRIGE'; Identite=$status.myID }; return }
    # Private configuration backup remains local. Never transmit this file.
    $backup = Join-Path $base ('Etat\config-avant-reparation-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '.xml')
    Copy-Item -LiteralPath $configPath -Destination $backup
    $remoteBefore = @($folder.devices | Where-Object { $_.deviceID -cne $ExpectedDeviceId }) | ConvertTo-Json -Depth 10 -Compress
    $self[0].encryptionPassword = ''
    $body = @{ devices = @($folder.devices) } | ConvertTo-Json -Depth 10 -Compress
    Invoke-RestMethod "$url/config/folders/$folderId" -Method Patch -Headers $headers -ContentType 'application/json' -Body $body | Out-Null
    $after = Invoke-RestMethod "$url/config/folders/$folderId" -Headers $headers
    $afterStatus = Invoke-RestMethod "$url/system/status" -Headers $headers
    $remoteAfter = @($after.devices | Where-Object { $_.deviceID -cne $ExpectedDeviceId }) | ConvertTo-Json -Depth 10 -Compress
    $localAfter = @($after.devices | Where-Object { $_.deviceID -ceq $ExpectedDeviceId })
    if ($afterStatus.myID -cne $ExpectedDeviceId -or $remoteBefore -cne $remoteAfter -or $localAfter.Count -ne 1 -or -not [string]::IsNullOrEmpty([string]$localAfter[0].encryptionPassword)) { throw 'Verification apres reparation non satisfaite. Ne pas restaurer automatiquement.' }
    [pscustomobject]@{ Statut='CORRIGE'; Identite=$afterStatus.myID; AppareilsDistantsInchanges=$true; ChiffrementLocalRenseigne=$false; SauvegardeConfigurationLocale=$true; FichiersTouches=$false; Redemarrage=$false }
} finally { Remove-Variable headers,xml,body,config,folder,self,remoteBefore,remoteAfter -ErrorAction SilentlyContinue }

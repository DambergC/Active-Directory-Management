#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
Back up or restore a local folder's NTFS security and direct SMB shares.
Restore also resets every existing subfolder and file to inherit only from
the restored folder (explicit permissions and blocked inheritance are removed).
.EXAMPLE
.\FolderSettings.ps1 -Mode Backup -FolderPath 'D:\Application\Data' -XmlPath 'C:\Backups\Data.xml'
.EXAMPLE
.\FolderSettings.ps1 -Mode Restore -XmlPath 'C:\Backups\Data.xml' -WhatIf
.EXAMPLE
.\FolderSettings.ps1 -Mode Restore -XmlPath 'C:\Backups\Data.xml'
.NOTES
Run elevated on the same Windows computer, using Windows PowerShell 5.1.
The folder must already exist when restoring. Back up XML outside the folder.
Captures owner, group, DACL, inheritance flags, and direct SMB share settings.
Use -IncludeAudit during backup to also capture and restore the SACL; this
requires the Manage auditing and security log privilege. Restoring ownership
can also require the Restore files and directories privilege.
Does not back up contents, child ACLs, parent ACLs, DFS, clustered shares,
administrative shares, temporary shares, or server-wide SMB configuration.
Owners of subfolders and files are kept. Junctions and symbolic links are
reset themselves but never followed. Permissions limited to "This folder only"
are not inherited by subfolders and files.
Shares not present in the backup are left unchanged during restore.
Inherited permissions depend on the parent ACL remaining unchanged.
Protect the XML from tampering; restore only a trusted backup.
Restore is not transactional: a failure can leave earlier changes applied.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Backup', 'Restore')]
    [string] $Mode,

    [string] $FolderPath,

    [Parameter(Mandatory = $true)]
    [string] $XmlPath,

    [switch] $IncludeAudit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module SmbShare -ErrorAction Stop

function Get-LocalFolder {
    param([string] $Path)
    if ($Path -notmatch '^[A-Za-z]:\\') {
        throw 'Use an absolute local path, for example D:\Application\Data.'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The target must be an existing directory, not a junction or symbolic link.'
    }
    $fullPath = $item.FullName.TrimEnd('\')
    if ($fullPath -eq [IO.Path]::GetPathRoot($item.FullName).TrimEnd('\')) {
        throw 'Volume roots are not supported.'
    }
    return $fullPath
}

function Reset-ChildPermissions {
    param([string] $Path)
    $directories = New-Object 'System.Collections.Generic.Stack[string]'
    $directories.Push($Path)
    while ($directories.Count -gt 0) {
        $directory = $directories.Pop()
        $children = @(Get-ChildItem -LiteralPath $directory -Force)
        if ($children.Count -eq 0) {
            continue
        }
        # /l resets links themselves; the recursion below never follows reparse points.
        & icacls.exe ($directory.TrimEnd('\') + '\*') /reset /l /q | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not reset permissions under '$directory' (icacls exit code $LASTEXITCODE)."
        }
        foreach ($child in $children) {
            if ($child.PSIsContainer -and
                -not ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                $directories.Push($child.FullName)
            }
        }
    }
}

$sections = [Security.AccessControl.AccessControlSections]::Access -bor
    [Security.AccessControl.AccessControlSections]::Owner -bor
    [Security.AccessControl.AccessControlSections]::Group
$newCommand = Get-Command New-SmbShare
$setCommand = Get-Command Set-SmbShare
$properties = @(
    'Description', 'ConcurrentUserLimit', 'CachingMode',
    'FolderEnumerationMode', 'EncryptData', 'CompressData', 'LeasingMode'
)

if ($Mode -eq 'Backup') {
    $folder = Get-LocalFolder $FolderPath
    $xmlFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($XmlPath)
    if ($xmlFile -eq $folder -or $xmlFile.StartsWith(
            $folder + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Store the XML outside the folder being backed up.'
    }
    if (Test-Path -LiteralPath $xmlFile) {
        throw "Backup already exists; choose a new XML filename: $xmlFile"
    }
    if ($IncludeAudit) {
        $sections = $sections -bor [Security.AccessControl.AccessControlSections]::Audit
    }
    $acl = Get-Acl -LiteralPath $folder -Audit:$IncludeAudit
    $shares = @(foreach ($share in Get-SmbShare) {
        if ([string]::IsNullOrWhiteSpace($share.Path) -or
            $share.Path.TrimEnd('\') -ne $folder) {
            continue
        }
        if ($share.Special -or $share.Temporary -or $share.Scoped -or
            [string]$share.AvailabilityType -ne 'NonClustered' -or
            $share.ContinuouslyAvailable) {
            throw "Unsupported administrative, temporary, or clustered share: $($share.Name)"
        }
        if ([string]::IsNullOrWhiteSpace($share.SecurityDescriptor)) {
            throw "Could not read the security descriptor for share $($share.Name)."
        }
        $settings = [ordered]@{
            SecurityDescriptor = [string]$share.SecurityDescriptor
        }
        foreach ($name in $properties) {
            if ($null -ne $share.PSObject.Properties[$name] -and
                $null -ne $share.$name) {
                if (-not $newCommand.Parameters.ContainsKey($name) -or
                    -not $setCommand.Parameters.ContainsKey($name)) {
                    throw "This SMB module cannot restore the share setting '$name'."
                }
                $settings[$name] = if ($share.$name -is [Enum]) {
                    [string]$share.$name
                } else {
                    $share.$name
                }
            }
        }
        [pscustomobject]@{ Name = $share.Name; Settings = $settings }
    })
    $backup = [pscustomobject]@{
        Version = 1
        ComputerName = $env:COMPUTERNAME
        FolderPath = $folder
        IncludeAudit = [bool]$IncludeAudit
        NtfsSddl = $acl.GetSecurityDescriptorSddlForm($sections)
        Shares = $shares
    }
    if ($PSCmdlet.ShouldProcess($xmlFile, 'Save folder security and SMB shares')) {
        $backup | Export-Clixml -LiteralPath $xmlFile -Depth 10 -Encoding UTF8 -NoClobber
        Write-Output "Saved settings for '$folder' to '$xmlFile' ($($shares.Count) shares)."
    }
    return
}

if ($IncludeAudit) {
    Write-Warning '-IncludeAudit is ignored during restore; the audit selection saved in the XML is used.'
}
$backup = Import-Clixml -LiteralPath $XmlPath
if ($backup.Version -ne 1 -or $backup.ComputerName -ne $env:COMPUTERNAME) {
    throw 'Unsupported backup version or different computer. Restore on the original computer.'
}
$folder = Get-LocalFolder $backup.FolderPath
if ($FolderPath -and (Get-LocalFolder $FolderPath) -ne $folder) {
    throw "-FolderPath '$FolderPath' does not match the folder saved in the XML: '$folder'."
}
if ($backup.IncludeAudit) {
    $sections = $sections -bor [Security.AccessControl.AccessControlSections]::Audit
}

# Preflight every share before modifying permissions or publishing a share.
$existingShares = @(Get-SmbShare)
$plans = @(foreach ($saved in $backup.Shares) {
    $existing = @($existingShares | Where-Object { $_.Name -eq $saved.Name })
    if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and (
            $existing[0].Path.TrimEnd('\') -ne $folder -or
            $existing[0].Special -or $existing[0].Temporary -or
            $existing[0].Scoped -or
            [string]$existing[0].AvailabilityType -ne 'NonClustered' -or
            $existing[0].ContinuouslyAvailable))) {
        throw "Share '$($saved.Name)' conflicts with another path or unsupported share."
    }
    $settings = @{}
    foreach ($name in $saved.Settings.Keys) {
        if ($name -notin ($properties + 'SecurityDescriptor') -or
            -not $newCommand.Parameters.ContainsKey($name) -or
            -not $setCommand.Parameters.ContainsKey($name)) {
            throw "Unsupported saved share setting: $name"
        }
        $settings[$name] = $saved.Settings[$name]
    }
    if ([string]::IsNullOrWhiteSpace($settings.SecurityDescriptor)) {
        throw "Missing security descriptor for share '$($saved.Name)'."
    }
    [pscustomobject]@{
        Name = [string]$saved.Name
        Exists = $existing.Count -eq 1
        Settings = $settings
    }
})

if ($PSCmdlet.ShouldProcess($folder,
        'Restore NTFS security, reset all subfolders and files to inherit it, and restore SMB shares')) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($backup.NtfsSddl, $sections)
    Set-Acl -LiteralPath $folder -AclObject $acl
    $actualAcl = Get-Acl -LiteralPath $folder -Audit:([bool]$backup.IncludeAudit)
    if ($actualAcl.GetSecurityDescriptorSddlForm($sections) -cne $backup.NtfsSddl) {
        throw 'NTFS security differs after restore. Check privileges and inherited parent permissions.'
    }
    Reset-ChildPermissions $folder
    foreach ($plan in $plans) {
        $settings = $plan.Settings
        if ($plan.Exists) {
            Set-SmbShare -Name $plan.Name -ScopeName '*' @settings -Force -Confirm:$false
        } else {
            New-SmbShare -Name $plan.Name -Path $folder @settings -Confirm:$false | Out-Null
        }
        $actual = Get-SmbShare -Name $plan.Name -ScopeName '*'
        foreach ($name in $settings.Keys) {
            if ([string]$actual.$name -cne [string]$settings[$name]) {
                throw "Share '$($plan.Name)': '$name' differs after restore."
            }
        }
    }
    Write-Output "Restored settings for '$folder' ($($plans.Count) shares)."
}

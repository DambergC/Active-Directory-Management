# Active-Directory-Management

Collection of scripts for Active Directory and Windows administration.

## Table of contents

| Script | Instructions | Purpose |
|---|---|---|
| [`Create-ADgroupAndGPO.ps1`](Create-ADgroupAndGPO.ps1) | [Create AD groups and GPOs](#create-adgroupandgpops1) | Create per-computer security groups and GPOs. |
| [`FolderSettings.ps1`](FolderSettings.ps1) | [Back up and restore folder settings](#foldersettingsps1) | Backup and restore NTFS security and SMB shares. |
| [`Get-EnvironmentHealth.ps1`](Get-EnvironmentHealth.ps1) | [Collect an environment health report](#get-environmenthealthps1) | Read-only AD, server and Configuration Manager checks. |

## Scripts

### Get-EnvironmentHealth.ps1

Collects a read-only report containing direct and recursively resolved members of Domain Admins, Enterprise Admins and Backup Operators; new server computer objects; gMSA inventory and optional host tests; expiring certificates; Configuration Manager site version and backup messages; fixed-disk free space; last boot time; and privileged logon events.

#### Prerequisites

- Windows PowerShell 5.1 or later on a domain-connected Windows computer with the ActiveDirectory RSAT module and read access to AD. The script runs in the current user's security context and makes no configuration changes.
- WinRM/PowerShell remoting and permission to read the LocalMachine certificate store on each server. gMSA tests also require the ActiveDirectory module on each specified host and permission to run `Test-ADServiceAccount` there.
- Remote CIM/WMI access to each server and the Configuration Manager SMS Provider, including permission to read the site namespace and status messages.
- Permission to read the Security event log on every explicitly specified log server. Relevant audit policies must be enabled and events must still be retained.

#### How to run

```powershell
$report = .\Get-EnvironmentHealth.ps1 `
    -Servers 'srv01.corp.example.com', 'srv02.corp.example.com' `
    -LogServers 'dc01.corp.example.com', 'dc02.corp.example.com', 'srv01.corp.example.com' `
    -GmsaTests @{ 'srv01.corp.example.com' = @('svcApp') } `
    -SccmProvider 'sccm01.corp.example.com' -SiteCode 'ABC'

$report | Select-Object Check, Target, Status, Detail | Format-Table -Wrap
$report | Where-Object { $_.Status -ne 'OK' } | Format-List
$report | Where-Object { $_.Check -eq 'Privileged logons' } | Select-Object -ExpandProperty Data
$report | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 'C:\Reports\environment-health.json'
```

Create the report directory first and restrict access to the resulting file: membership, hostnames and security events can be sensitive. Omit optional targets to skip those checks; skipped checks are reported as `NotConfigured`, not as healthy. Each result has `Check`, `Target`, `Status`, `Detail` and a `Data` array. `Warning` means an observed threshold or backup condition needs review, `Error` means collection failed, and `Partial` means logon matching may be incomplete. An AD initialization failure stops the script; individual check failures are returned as results. Empty `Data` is not proof of health if the status is not `OK`.

| Parameter | Default | Description |
|---|---|---|
| `Servers` | None | Explicit critical servers for certificates, disks and boot times. |
| `LogServers` | None | Computers whose local Security logs are queried; include all relevant DCs and servers. |
| `GmsaTests` | None | Hashtable of host names to arrays of installed gMSA names to test on those hosts. |
| `SccmProvider`, `SiteCode` | None | SMS Provider host and three-character site code; provide both or neither. |
| `NewServerDays` | 30 | Lookback for server computer-object creation. |
| `CertificateDays` | 60 | Report certificates expiring in fewer than this many days, including expired certificates. |
| `LogonDays` | 1 | Security event lookback in days. |
| `BackupMaxAgeDays` | 2 | Lookback for Configuration Manager backup status messages. |
| `DiskFreePercent` | 20 | Warn when a fixed logical disk has strictly less than this percentage free. |

#### Scope and interpretation

- Group checks cover the current domain's Domain Admins and built-in Backup Operators and the forest root's Enterprise Admins. Membership is resolved at report time; foreign principals or inaccessible domains can prevent recursive resolution. Review both direct and effective entries; a failure makes the logon check `Partial`.
- New servers are AD computer objects created during the lookback whose `operatingSystem` attribute contains `Server`; stale or missing attributes and other domains are not covered.
- gMSA inventory is AD configuration, not proof that an account works. `GmsaTests` tests only the named accounts on the named hosts, not every possible host.
- Certificates are limited to `Cert:\LocalMachine\My` on `Servers`; other stores, user certificates and certificate authorities are not scanned.
- SCCM backup reports success message 5035 and subsequent warning/error status messages from `SMS_SITE_BACKUP` within the lookback. `OK` indicates a recent success message with no later warning/error in that window, not that a later backup completed or that a restore will work. Other backup products and SQL-only backups are not checked. See [Microsoft's status-message reference](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/servers/manage/sms_statusmessage-server-wmi-class).
- Logons include event 4624 when the target SID matches a currently resolved member of the three groups, plus **all** event 4672 special-privilege assignments, including service and system accounts. Event 4672 can be correlated with 4624 via `LogonId` on the same host. Group membership at the time of an event, other privileged groups, events on unlisted hosts, missing audit policy and expired logs are not covered. Results can be large.
- Disk checks cover fixed logical disks only, not unmounted volumes or network shares. Last boot time is informational, not an uptime alert.

For full help, run `Get-Help .\Get-EnvironmentHealth.ps1 -Full`.

### Create-ADgroupAndGPO.ps1

Creates one global security group and one GPO per computer found in a given OU (including nested OUs). The GPO adds the group to a local group on the computer — `Administrators` by default, or `Remote Desktop Users`, `Users`, or any custom local group via `-LocalGroup` — using Group Policy Preferences. The GPO is security-filtered so it only applies to that specific computer and is linked to the computer's OU. Domain controllers are excluded.

#### Prerequisites

- Windows PowerShell 5.1 or later
- RSAT PowerShell modules:
  - `ActiveDirectory`
  - `GroupPolicy`

  Install on Windows Server: `Install-WindowsFeature RSAT-AD-PowerShell, GPMC`
  Install on Windows 10/11: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0; Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0`
- An account with permissions to:
  - Create security groups in the target group OU
  - Create and link GPOs in the domain (writes to SYSVOL)
- Network access to the PDC emulator (all changes are made against it)
- Write access to the log file location (defaults to the script folder)

#### How to run

Always start with `-WhatIf` to preview what would be created:

```powershell
.\Create-ADgroupAndGPO.ps1 `
    -ServerOU 'OU=Servers,DC=corp,DC=example,DC=com' `
    -GroupOU 'OU=AdminGroups,DC=corp,DC=example,DC=com' `
    -WhatIf
```

Then run it for real:

```powershell
.\Create-ADgroupAndGPO.ps1 `
    -ServerOU 'OU=Servers,DC=corp,DC=example,DC=com' `
    -GroupOU 'OU=AdminGroups,DC=corp,DC=example,DC=com'
```

With custom naming templates (`{ServerName}` is required, `{OUPath}` is optional and includes a trailing hyphen when nonempty):

```powershell
.\Create-ADgroupAndGPO.ps1 `
    -ServerOU 'OU=Servers,DC=corp,DC=example,DC=com' `
    -GroupOU 'OU=AdminGroups,DC=corp,DC=example,DC=com' `
    -GroupNameTemplate 'ADM-{ServerName}' `
    -GpoNameTemplate 'GPO-LocalAdmin-{OUPath}{ServerName}'
```

Target another local group than `Administrators` (built-in groups `Administrators`, `Remote Desktop Users` and `Users` are targeted by their well-known SIDs; any other value is treated as a custom local group that the GPO creates on the computer if it does not exist — adjust the name templates to match):

```powershell
.\Create-ADgroupAndGPO.ps1 `
    -ServerOU 'OU=Servers,DC=corp,DC=example,DC=com' `
    -GroupOU 'OU=AdminGroups,DC=corp,DC=example,DC=com' `
    -LocalGroup 'Remote Desktop Users' `
    -GroupNameTemplate 'SEC-{OUPath}{ServerName}-RDP' `
    -GpoNameTemplate 'LocalRDP-{OUPath}{ServerName}'
```

Repair a single computer where the group and an empty, unlinked managed GPO already exist:

```powershell
.\Create-ADgroupAndGPO.ps1 `
    -ServerOU 'OU=Servers,DC=corp,DC=example,DC=com' `
    -GroupOU 'OU=AdminGroups,DC=corp,DC=example,DC=com' `
    -RepairServer 'SRV01'
```

#### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `ServerOU` | Yes | – | OU containing the computer accounts (nested OUs are searched) |
| `GroupOU` | Yes | – | OU where the security groups are created |
| `GroupNameTemplate` | No | `SEC-{OUPath}{ServerName}-Admin` | Name template for groups |
| `GpoNameTemplate` | No | `LocalAdmin-{OUPath}{ServerName}` | Name template for GPOs |
| `LocalGroup` | No | `Administrators` | Local group the AD group is added to: `Administrators`, `Remote Desktop Users`, `Users`, or a custom local group name |
| `RepairServer` | No | – | Repair a single named computer |
| `LogFile` | No | `Create-ServerAdminGpo.log` next to the script | Transcript log path; pass `''` to disable |

#### Behavior and safety

- Supports `-WhatIf` and `-Confirm` (ShouldProcess).
- Computers that already have both a matching group and GPO are skipped.
- The script validates naming collisions, group name length, GPO state and security filtering before linking, and aborts a computer with a warning if anything is unexpected.
- All actions are logged to a transcript file (unless `-WhatIf` is used or logging is disabled).

For full help, run:

```powershell
Get-Help .\Create-ADgroupAndGPO.ps1 -Full
```

### FolderSettings.ps1

Backs up a local folder's NTFS security and direct SMB shares to XML, then restores them after the folder has been recreated. It saves the folder's owner, group, permissions and inheritance settings, plus share permissions and supported share properties. Auditing rules are optional.

#### Prerequisites

- Windows PowerShell 5.1 or later, running as administrator, and the `SmbShare` module.
- Run on the source computer for backup and on the destination computer for restore. The destination may be another server, but the folder must exist at the same saved local path; the script does **not** create it. Volume roots, junctions and symbolic links cannot be selected as the target folder.
- Store the XML outside the target folder, in an existing directory. The script will not overwrite an existing backup. Protect the file from tampering and restore only a trusted backup.
- Restoring ownership may require the **Restore files and directories** privilege. Backing up and restoring audit rules with `-IncludeAudit` requires the **Manage auditing and security log** privilege.

#### How to run

Before the upgrade, save the settings:

```powershell
.\FolderSettings.ps1 -Mode Backup -FolderPath 'D:\Application\Data' -XmlPath 'C:\Backups\Data.xml'
```

To include the target folder's auditing rules, add `-IncludeAudit` to the backup command. The restore uses the audit selection saved in the XML.

Copy the XML to the destination server, recreate the folder at the same local path, then preview and restore:

```powershell
.\FolderSettings.ps1 -Mode Restore -XmlPath 'C:\Backups\Data.xml' -WhatIf
.\FolderSettings.ps1 -Mode Restore -XmlPath 'C:\Backups\Data.xml'
```

`-FolderPath` is optional during restore; if specified, it must match the path saved in the XML. `-WhatIf` previews the operation and does not change permissions or shares.

#### Parameters

| Parameter | Required | Description |
|---|---|---|
| `Mode` | Yes | `Backup` or `Restore`. |
| `FolderPath` | Backup only | Existing absolute local folder path; optional on restore and must match the saved path. |
| `XmlPath` | Yes | Backup XML file path. |
| `IncludeAudit` | No | Include the target folder's audit rules in the backup; ignored on restore. |

#### Behavior and safety

- Restore replaces the selected folder's saved NTFS security, including owner and group. It resets existing descendant permissions to inherited permissions: **explicit permissions on subfolders and files are removed**, and blocked inheritance is reset. Child owners are not changed. Only permissions configured for inheritance apply to children; permissions limited to the target folder do not propagate.
- Account SIDs in NTFS and share security descriptors are restored unchanged. Domain accounts must be available on the destination; source-server local accounts have different SIDs on another server and may not resolve or grant access. The script does not remap accounts.
- The script updates matching saved SMB shares or recreates missing shares pointing to the existing folder. It does not create the folder. Conflicting share names stop restore, and shares absent from the backup are left unchanged.
- File contents and individual child ACLs are not backed up. Parent ACLs are not saved, so different parent permissions on the destination can affect inherited permissions or cause verification to fail. Junctions and symbolic links below the target are not followed.
- DFS, administrative, temporary and clustered shares, as well as server-wide SMB settings, are not backed up. Restore is not transactional: if an error occurs, earlier changes may already have been applied.

For full help, run:

```powershell
Get-Help .\FolderSettings.ps1 -Full
```

# Active-Directory-Management

Collection of scripts for Active Directory and Windows administration.

## Table of contents

| Script | Instructions | Purpose |
|---|---|---|
| [`Create-ADgroupAndGPO.ps1`](Create-ADgroupAndGPO.ps1) | [Create AD groups and GPOs](#create-adgroupandgpops1) | Create per-computer security groups and GPOs. |
| [`FolderSettings.ps1`](FolderSettings.ps1) | [Back up and restore folder settings](#foldersettingsps1) | Back up and restore NTFS security and SMB shares. |

## Scripts

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
- Run on the original computer. The folder must exist at the saved local path for both backup and restore; the script does **not** create it. Volume roots, junctions and symbolic links cannot be selected as the target folder.
- Store the XML outside the target folder, in an existing directory. The script will not overwrite an existing backup. Protect the file from tampering and restore only a trusted backup.
- Restoring ownership may require the **Restore files and directories** privilege. Backing up and restoring audit rules with `-IncludeAudit` requires the **Manage auditing and security log** privilege.

#### How to run

Before the upgrade, save the settings:

```powershell
.\FolderSettings.ps1 -Mode Backup -FolderPath 'D:\Application\Data' -XmlPath 'C:\Backups\Data.xml'
```

To include the target folder's auditing rules, add `-IncludeAudit` to the backup command. The restore uses the audit selection saved in the XML.

After the upgrade, recreate the folder at the same path, then preview and restore:

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
- The script updates matching saved SMB shares or recreates missing shares pointing to the existing folder. It does not create the folder. Conflicting share names stop restore, and shares absent from the backup are left unchanged.
- File contents and individual child ACLs are not backed up. Parent ACLs are not saved, so changes to the parent can affect inherited permissions. Junctions and symbolic links below the target are not followed.
- DFS, administrative, temporary and clustered shares, as well as server-wide SMB settings, are not backed up. Restore is not transactional: if an error occurs, earlier changes may already have been applied.

For full help, run:

```powershell
Get-Help .\FolderSettings.ps1 -Full
```

# Active-Directory-Management

Collection of scripts to use in management of Active Directory.

## Scripts

### Create-ADgroupAndGPO.ps1

Creates one global security group and one GPO per computer found in a given OU (including nested OUs). The GPO adds the group to the local `Administrators` group via Group Policy Preferences, is security-filtered so it only applies to that specific computer, and is linked to the computer's OU. Domain controllers are excluded.

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

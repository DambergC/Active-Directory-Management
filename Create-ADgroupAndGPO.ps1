#requires -Version 5.1
#requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
Creates one AD security group and one local administrator GPO per computer.

.DESCRIPTION
Searches ServerOU and nested OUs for computer accounts (domain controllers
are excluded). For each computer it creates a global security group in
GroupOU and a GPO that adds the group to the local Administrators group via
Group Policy Preferences, then links the GPO to the computer's OU with
security filtering so it only applies to that computer.

Use {ServerName} and optionally {OUPath} in either name template. OUPath
includes a trailing hyphen when nonempty. An existing group and GPO are
skipped by default. RepairServer processes only one computer and only
finishes a matching, empty, unlinked managed GPO.

All actions are written to a transcript log unless -WhatIf is used.

.PARAMETER ServerOU
Distinguished name (or GUID) of the OU that contains the computer accounts.
Nested OUs are searched as well.

.PARAMETER GroupOU
Distinguished name (or GUID) of the OU where the security groups are created.

.PARAMETER GroupNameTemplate
Name template for the security groups. Must contain {ServerName} and may
contain {OUPath}. Default: 'SEC-{OUPath}{ServerName}-Admin'.

.PARAMETER GpoNameTemplate
Name template for the GPOs. Must contain {ServerName} and may contain
{OUPath}. Default: 'LocalAdmin-{OUPath}{ServerName}'.

.PARAMETER RepairServer
Name of a single computer to repair. Requires that both the group and a
matching, empty, unlinked managed GPO already exist; the script then
finishes the configuration for that computer only.

.PARAMETER LogFile
Path to the transcript log file. Defaults to
'Create-ServerAdminGpo.log' next to the script. Pass an empty string to
disable logging.

.EXAMPLE
.\Create-ADgroupAndGPO.ps1 -ServerOU 'OU=Servers,DC=corp,DC=example,DC=com' -GroupOU 'OU=AdminGroups,DC=corp,DC=example,DC=com' -WhatIf

Shows what would be created without changing anything.

.EXAMPLE
.\Create-ADgroupAndGPO.ps1 -ServerOU 'OU=Servers,DC=corp,DC=example,DC=com' -GroupOU 'OU=AdminGroups,DC=corp,DC=example,DC=com'

Creates a group and a linked local administrator GPO for every computer
under the Servers OU.

.EXAMPLE
.\Create-ADgroupAndGPO.ps1 -ServerOU 'OU=Servers,DC=corp,DC=example,DC=com' -GroupOU 'OU=AdminGroups,DC=corp,DC=example,DC=com' -GroupNameTemplate 'ADM-{ServerName}' -GpoNameTemplate 'GPO-LocalAdmin-{OUPath}{ServerName}'

Uses custom naming templates for groups and GPOs.

.EXAMPLE
.\Create-ADgroupAndGPO.ps1 -ServerOU 'OU=Servers,DC=corp,DC=example,DC=com' -GroupOU 'OU=AdminGroups,DC=corp,DC=example,DC=com' -RepairServer 'SRV01'

Finishes the configuration for SRV01 where the group and an empty,
unlinked managed GPO already exist.

.NOTES
Author:  Christian Damberg (DambergC)
Company: Telia Cygate AB
Created: 2026-11-19

Requires PowerShell 5.1+, the ActiveDirectory and GroupPolicy modules
(RSAT), and permissions to create groups, create/link GPOs and write to
SYSVOL. All changes are made against the PDC emulator.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$ServerOU,
    [Parameter(Mandatory)] [string]$GroupOU,
    [string]$GroupNameTemplate = 'SEC-{OUPath}{ServerName}-Admin',
    [string]$GpoNameTemplate = 'LocalAdmin-{OUPath}{ServerName}',
    [string]$RepairServer,
    [string]$LogFile = "$PSScriptRoot\Create-ServerAdminGpo.log"
)

$ErrorActionPreference = 'Stop'

function Get-ParentDn([string]$Dn) {
    # Do not split at escaped commas in a relative distinguished name.
    ($Dn -split '^(?:\\.|[^\\,])+,', 2)[-1]
}

function Get-FormattedName {
    param(
        [string]$Template,
        [string]$ServerName,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$OUPath
    )
    $Template.Replace('{OUPath}', $OUPath).Replace('{ServerName}', $ServerName).Trim()
}

function Get-GroupSamAccountName([string]$Name) {
    if ($Name -match '^[A-Za-z0-9._-]{1,20}$' -and -not $Name.EndsWith('.')) {
        return $Name
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Name.ToUpperInvariant())
        $hex = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '')
        return 'S' + $hex.Substring(0, 19)
    }
    finally {
        $sha.Dispose()
    }
}

function Get-EmptyPolicyFiles($Gpo) {
    $id = $Gpo.Id.ToString('B').ToUpperInvariant()
    $dn = "CN=$id,CN=Policies,CN=System,$($domain.DistinguishedName)"
    $path = "\\$dc\SYSVOL\$($domain.DNSRoot)\Policies\$id"
    $policy = Get-ADObject -Identity $dn -Server $dc `
        -Properties versionNumber, gPCMachineExtensionNames, gPCUserExtensionNames
    $gptIni = Join-Path $path 'GPT.INI'
    $ini = Get-Content -LiteralPath $gptIni -Raw
    $groupsDir = Join-Path $path 'Machine\Preferences\Groups'
    $groupsXml = Join-Path $groupsDir 'Groups.xml'

    if ($policy.versionNumber -ne 0 -or $policy.gPCMachineExtensionNames -or
        $policy.gPCUserExtensionNames -or $ini -notmatch '(?im)^Version=0[ \t]*\r?$' -or
        (Test-Path -LiteralPath $groupsXml)) {
        throw "GPO '$($Gpo.DisplayName)' ar inte tom. Granska den i GPMC."
    }

    [pscustomobject]@{
        Dn        = $dn
        GptIni    = $gptIni
        Ini       = $ini
        GroupsDir = $groupsDir
        GroupsXml = $groupsXml
    }
}

function Set-LocalAdminPreference($Files, $Group) {
    $memberName = [System.Security.SecurityElement]::Escape(
        "$($domain.NetBIOSName)\$($Group.SamAccountName)"
    )
    $memberSid = $Group.SID.Value
    $uid = [guid]::NewGuid().ToString('B').ToUpperInvariant()
    $changed = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    [xml]$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4B4C-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="$changed" uid="$uid">
    <Properties action="U" groupName="Administrators (built-in)" groupSid="S-1-5-32-544" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0">
      <Members>
        <Member name="$memberName" action="ADD" sid="$memberSid" />
      </Members>
    </Properties>
  </Group>
</Groups>
"@

    # GroupPolicy has no cmdlet for this Group Policy Preferences setting.
    $null = New-Item -Path $Files.GroupsDir -ItemType Directory -Force
    $xml.Save($Files.GroupsXml)
    $ini = $Files.Ini -replace '(?im)^Version=0[ \t]*(?=\r?$)', 'Version=1'
    Set-Content -LiteralPath $Files.GptIni -Value $ini -Encoding ASCII -NoNewline
    Set-ADObject -Identity $Files.Dn -Server $dc -Replace @{
        gPCMachineExtensionNames = '[{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]'
        versionNumber            = 1
    }
}

foreach ($template in @($GroupNameTemplate, $GpoNameTemplate)) {
    if (-not $template.Contains('{ServerName}') -or
        $template.Replace('{ServerName}', '').Replace('{OUPath}', '') -match '[{}]') {
        throw "Ogiltig namnmall '$template'. Anvand {ServerName} och valfritt {OUPath}."
    }
}

$transcriptStarted = $false
try {
    if (-not $WhatIfPreference -and $LogFile) {
        $logDir = Split-Path -Path $LogFile -Parent
        if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
            $null = New-Item -Path $logDir -ItemType Directory -Force
        }
        Start-Transcript -Path $LogFile -Append | Out-Null
        $transcriptStarted = $true
    }

    $domain = Get-ADDomain
    $dc = $domain.PDCEmulator
    $gp = @{ Domain = $domain.DNSRoot; Server = $dc }
    $rootDn = (Get-ADOrganizationalUnit -Identity $ServerOU -Server $dc).DistinguishedName
    $groupDn = (Get-ADOrganizationalUnit -Identity $GroupOU -Server $dc).DistinguishedName
    $authenticatedUsers = (
        [System.Security.Principal.SecurityIdentifier]'S-1-5-11'
    ).Translate([System.Security.Principal.NTAccount]).Value

    $ous = @{}
    Get-ADOrganizationalUnit -SearchBase $rootDn -SearchScope Subtree `
        -Filter * -Server $dc | ForEach-Object { $ous[$_.DistinguishedName] = $_.Name }

    $groups = @{}
    Get-ADGroup -SearchBase $groupDn -SearchScope OneLevel -Filter * `
        -Server $dc | ForEach-Object { $groups[$_.Name] = $_ }

    $gpos = @{}
    Get-GPO -All @gp | ForEach-Object { $gpos[$_.DisplayName] += @($_) }

    $servers = @(Get-ADComputer -SearchBase $rootDn -SearchScope Subtree -Server $dc `
        -LDAPFilter '(&(!(primaryGroupID=516))(!(primaryGroupID=521))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))')

    $plan = @(
        foreach ($server in $servers) {
            $parent = Get-ParentDn $server.DistinguishedName
            $ouDn = $parent
            $segments = @()
            while ($parent -ne $rootDn) {
                if (-not $ous.ContainsKey($parent)) {
                    throw "Datorn '$($server.Name)' ligger inte direkt i ett OU under '$ServerOU'."
                }
                $segment = ($ous[$parent] -replace '[^\p{L}\p{N}._-]+', '-').Trim('-')
                if (-not $segment) {
                    throw "OU '$($ous[$parent])' kan inte anvandas i namnstandarden."
                }
                $segments = @($segment) + $segments
                $parent = Get-ParentDn $parent
            }

            $ouPath = ''
            if ($segments.Count) { $ouPath = ($segments -join '-') + '-' }
            [pscustomobject]@{
                Server    = $server
                OuDn      = $ouDn
                GroupName = Get-FormattedName -Template $GroupNameTemplate `
                    -ServerName $server.Name -OUPath $ouPath
                GpoName   = Get-FormattedName -Template $GpoNameTemplate `
                    -ServerName $server.Name -OUPath $ouPath
            }
        }
    )

    foreach ($property in @('GroupName', 'GpoName')) {
        $collision = $plan | Group-Object -Property $property | Where-Object Count -gt 1
        if ($collision) {
            throw "Namnkrock i ${property}: $($collision.Name -join ', '). Andra namnstandarden."
        }
    }

    if ($RepairServer) {
        $plan = @($plan | Where-Object { $_.Server.Name -eq $RepairServer })
        if ($plan.Count -ne 1) {
            throw "Hittade inte exakt en server med namnet '$RepairServer'."
        }
    }
    Write-Host "Datorer att kontrollera: $($plan.Count)"

    $errors = 0
    foreach ($entry in $plan) {
        $server = $entry.Server
        $name = $server.Name
        $groupName = $entry.GroupName
        $gpoName = $entry.GpoName
        $group = $groups[$groupName]
        $matchesGpo = @($gpos[$gpoName] | Where-Object { $_ })
        $marker = "Managed by Create-ServerAdminGpo.ps1; Computer=$($server.ObjectGUID)"

        try {
            if ($group -and $matchesGpo.Count -and -not $RepairServer) {
                Write-Host "${name}: AD-gruppen '$groupName' och GPO:n '$gpoName' finns redan. Hoppar over."
                continue
            }
            if ($groupName.Length -gt 64) {
                throw "Gruppnamnet '$groupName' ar langre an 64 tecken. Anvand en kortare namnmall."
            }
            if ($matchesGpo.Count -gt 1) {
                throw "Flera GPO:er heter '$gpoName'."
            }

            $gpo = $null
            if ($matchesGpo.Count -eq 1) { $gpo = $matchesGpo[0] }
            if ($RepairServer -and (-not $gpo -or -not $group)) {
                throw "Reparation kraver att bade gruppen '$groupName' och GPO:n '$gpoName' redan finns."
            }
            if ($group -and ($group.GroupCategory -ne 'Security' -or $group.GroupScope -ne 'Global')) {
                throw "'$groupName' ar inte en global sakerhetsgrupp."
            }

            $files = $null
            if ($gpo) {
                if ($gpo.Description -ne $marker -or
                    $gpo.GpoStatus -notin @('AllSettingsEnabled', 'UserSettingsDisabled') -or
                    $gpo.WmiFilter) {
                    throw "GPO '$gpoName' matchar inte den forvantade konfigurationen."
                }

                [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml @gp
                if ($report.SelectSingleNode("/*[local-name()='GPO']/*[local-name()='LinksTo']/*[local-name()='SOMPath']")) {
                    throw "GPO '$gpoName' ar redan lankad. Granska den i GPMC."
                }
                $files = Get-EmptyPolicyFiles $gpo
            }

            if (-not $PSCmdlet.ShouldProcess(
                    "$name ($($entry.OuDn))", "Konfigurera '$groupName' via '$gpoName'")) {
                continue
            }

            if (-not $group) {
                Write-Host "${name}: Skapar '$groupName'."
                $group = New-ADGroup -Name $groupName -DisplayName $groupName `
                    -SamAccountName (Get-GroupSamAccountName $groupName) `
                    -Description "Lokala administratorer pa $name" -GroupCategory Security `
                    -GroupScope Global -Path $groupDn -Server $dc -PassThru
            }
            if (-not $gpo) {
                Write-Host "${name}: Skapar '$gpoName'."
                $gpo = New-GPO -Name $gpoName -Comment $marker @gp
                $files = Get-EmptyPolicyFiles $gpo
            }

            $target = "$($domain.NetBIOSName)\$($server.SamAccountName)"
            Set-GPPermission -Guid $gpo.Id -TargetName $authenticatedUsers -TargetType Group `
                -PermissionLevel GpoRead -Replace @gp | Out-Null
            Set-GPPermission -Guid $gpo.Id -TargetName $target -TargetType Computer `
                -PermissionLevel GpoApply -Replace @gp | Out-Null

            $apply = @(Get-GPPermission -Guid $gpo.Id -All @gp |
                Where-Object Permission -eq 'GpoApply')
            $computerPermission = Get-GPPermission -Guid $gpo.Id `
                -TargetName $target -TargetType Computer @gp
            if ($apply.Count -ne 1 -or $computerPermission.Permission -ne 'GpoApply') {
                throw "Ovantad sakerhetsfiltrering for '$gpoName'. GPO:n lankas inte."
            }

            Set-LocalAdminPreference $files $group
            New-GPLink -Guid $gpo.Id -Target $entry.OuDn -LinkEnabled Yes @gp | Out-Null
            Write-Host "${name}: Klart. '$groupName' laggs till via '$gpoName'."
        }
        catch {
            $errors++
            Write-Warning "${name}: $($_.Exception.Message)"
        }
    }

    if ($errors) {
        throw "$errors server/dator(er) kunde inte konfigureras. Se varningarna ovan."
    }
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}

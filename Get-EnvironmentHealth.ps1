<#
.SYNOPSIS
    Collects read-only AD, server and Configuration Manager health information.
.DESCRIPTION
    Returns one object per check and target. Status is OK, Warning, Error,
    Partial or NotConfigured. Data contains the underlying observations.
    See README.md for scope, prerequisites and limitations.
.EXAMPLE
    .\Get-EnvironmentHealth.ps1 -Servers 'srv01','srv02' -SccmProvider 'sccm01' -SiteCode 'ABC'
#>
[CmdletBinding()]
param(
    [string[]] $Servers = @(),
    [string[]] $LogServers = @(),
    [hashtable] $GmsaTests = @{},
    [string] $SccmProvider,
    [ValidatePattern('^[A-Za-z0-9]{3}$')]
    [string] $SiteCode,
    [ValidateRange(1, 3650)]
    [int] $NewServerDays = 30,
    [ValidateRange(1, 3650)]
    [int] $CertificateDays = 60,
    [ValidateRange(1, 3650)]
    [int] $LogonDays = 1,
    [ValidateRange(1, 3650)]
    [int] $BackupMaxAgeDays = 2,
    [ValidateRange(1, 99)]
    [int] $DiskFreePercent = 20
)

$ErrorActionPreference = 'Stop'
$now = Get-Date
$results = New-Object 'System.Collections.Generic.List[object]'
$privilegedSids = @{}
$membershipComplete = $true

function Add-Result {
    param([string] $Check, [string] $Target, [string] $Status,
          [string] $Detail, [object[]] $Data = @())
    $results.Add([pscustomobject]@{
        Check = $Check
        Target = $Target
        Status = $Status
        Detail = $Detail
        Data = @($Data)
    })
}

if (($SccmProvider -and -not $SiteCode) -or ($SiteCode -and -not $SccmProvider)) {
    throw 'Specify both -SccmProvider and -SiteCode, or neither.'
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    $rootDomain = Get-ADDomain -Identity $forest.RootDomain -ErrorAction Stop
} catch {
    throw "Active Directory initialization failed: $($_.Exception.Message)"
}

$groups = @(
    @{ Name = 'Domain Admins'; Sid = "$($domain.DomainSID.Value)-512"; Server = $domain.DNSRoot }
    @{ Name = 'Enterprise Admins'; Sid = "$($rootDomain.DomainSID.Value)-519"; Server = $rootDomain.DNSRoot }
    @{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551'; Server = $domain.DNSRoot }
)
foreach ($group in $groups) {
    try {
        $adGroup = Get-ADGroup -Identity $group.Sid -Server $group.Server -ErrorAction Stop
        $direct = @(Get-ADGroupMember -Identity $adGroup -Server $group.Server -ErrorAction Stop)
        $effective = @(Get-ADGroupMember -Identity $adGroup -Server $group.Server -Recursive -ErrorAction Stop)
        foreach ($member in $effective) {
            if ($member.SID) { $privilegedSids[$member.SID.Value] = $true }
        }
        $data = @(
            foreach ($member in $direct) {
                [pscustomobject]@{ Membership = 'Direct'; Name = $member.Name; SamAccountName = $member.SamAccountName; ObjectClass = $member.objectClass; SID = [string]$member.SID }
            }
            foreach ($member in $effective) {
                [pscustomobject]@{ Membership = 'Effective'; Name = $member.Name; SamAccountName = $member.SamAccountName; ObjectClass = $member.objectClass; SID = [string]$member.SID }
            }
        )
        Add-Result $group.Name $group.Server 'OK' "$($direct.Count) direct, $($effective.Count) recursively resolved members." $data
    } catch {
        $membershipComplete = $false
        Add-Result $group.Name $group.Server 'Error' $_.Exception.Message
    }
}

try {
    $cutoff = $now.AddDays(-$NewServerDays)
    $serversFound = @(Get-ADComputer -Filter { OperatingSystem -like '*Server*' -and whenCreated -ge $cutoff } -Properties OperatingSystem, whenCreated, DNSHostName -ErrorAction Stop |
        Select-Object Name, DNSHostName, OperatingSystem, whenCreated, DistinguishedName)
    Add-Result 'New AD servers' $domain.DNSRoot 'OK' "Computer objects created since $cutoff; based on the AD operatingSystem attribute." $serversFound
} catch {
    Add-Result 'New AD servers' $domain.DNSRoot 'Error' $_.Exception.Message
}

try {
    $accounts = @(Get-ADServiceAccount -Filter * -Properties Enabled, DNSHostName, PrincipalsAllowedToRetrieveManagedPassword -ErrorAction Stop |
        Where-Object { $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' } |
        Select-Object Name, SamAccountName, Enabled, DNSHostName, PrincipalsAllowedToRetrieveManagedPassword)
    Add-Result 'gMSA inventory' $domain.DNSRoot 'OK' 'AD inventory only; this does not verify passwords on hosts.' $accounts
} catch {
    Add-Result 'gMSA inventory' $domain.DNSRoot 'Error' $_.Exception.Message
}
if ($GmsaTests.Count -eq 0) {
    Add-Result 'gMSA test' '-' 'NotConfigured' 'Provide -GmsaTests with host-to-account mappings to test installed accounts.'
}
foreach ($hostName in $GmsaTests.Keys) {
    foreach ($accountName in @($GmsaTests[$hostName])) {
        try {
            if ([string]::IsNullOrWhiteSpace([string]$accountName)) { throw 'gMSA account name must not be empty.' }
            $test = Invoke-Command -ComputerName $hostName -ArgumentList ([string]$accountName) -ErrorAction Stop -ScriptBlock {
                param($Name)
                Import-Module ActiveDirectory -ErrorAction Stop
                Test-ADServiceAccount -Identity $Name -ErrorAction Stop
            }
            if ($test -isnot [bool]) { throw 'Test-ADServiceAccount did not return a Boolean result.' }
            $status = if ($test) { 'OK' } else { 'Warning' }
            Add-Result 'gMSA test' "$hostName/$accountName" $status "Test-ADServiceAccount returned $test."
        } catch {
            Add-Result 'gMSA test' "$hostName/$accountName" 'Error' $_.Exception.Message
        }
    }
}

if ($Servers.Count -eq 0) {
    foreach ($check in @('Certificates', 'Disk space', 'Last reboot')) {
        Add-Result $check '-' 'NotConfigured' 'Provide -Servers.'
    }
}
foreach ($server in $Servers) {
    try {
        $certs = @(Invoke-Command -ComputerName $server -ArgumentList $now.AddDays($CertificateDays) -ErrorAction Stop -ScriptBlock {
            param($Until)
            Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop |
                Where-Object { $_.NotAfter -lt $Until } |
                Select-Object Subject, Thumbprint, NotBefore, NotAfter, Issuer
        })
        $status = if ($certs.Count) { 'Warning' } else { 'OK' }
        Add-Result 'Certificates' $server $status "LocalMachine\My certificates expiring before $($now.AddDays($CertificateDays)); includes expired certificates." $certs
    } catch {
        Add-Result 'Certificates' $server 'Error' $_.Exception.Message
    }
    try {
        $disks = @(Get-CimInstance -ComputerName $server -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
            ForEach-Object {
                if (-not $_.Size) { throw "Disk $($_.DeviceID) has no usable size." }
                [pscustomobject]@{ DeviceID = $_.DeviceID; SizeGB = [math]::Round($_.Size / 1GB, 2); FreeGB = [math]::Round($_.FreeSpace / 1GB, 2); FreePercent = 100.0 * $_.FreeSpace / $_.Size }
            })
        if ($disks.Count -eq 0) { throw 'No fixed logical disks returned.' }
        $low = @($disks | Where-Object { $_.FreePercent -lt $DiskFreePercent })
        $status = if ($low.Count) { 'Warning' } else { 'OK' }
        Add-Result 'Disk space' $server $status "Warning below $DiskFreePercent% free on fixed logical disks." $disks
    } catch {
        Add-Result 'Disk space' $server 'Error' $_.Exception.Message
    }
    try {
        $os = Get-CimInstance -ComputerName $server -ClassName Win32_OperatingSystem -ErrorAction Stop
        if (-not $os.LastBootUpTime) { throw 'LastBootUpTime was not returned.' }
        Add-Result 'Last reboot' $server 'OK' 'Operating system last boot time.' @([pscustomobject]@{ LastBootUpTime = $os.LastBootUpTime })
    } catch {
        Add-Result 'Last reboot' $server 'Error' $_.Exception.Message
    }
}

if (-not $SccmProvider) {
    Add-Result 'SCCM version' '-' 'NotConfigured' 'Provide -SccmProvider and -SiteCode.'
    Add-Result 'SCCM backup' '-' 'NotConfigured' 'Provide -SccmProvider and -SiteCode.'
} else {
    $namespace = "root/SMS/site_$SiteCode"
    try {
        $site = @(Get-CimInstance -ComputerName $SccmProvider -Namespace $namespace -ClassName SMS_Site -Filter "SiteCode='$SiteCode'" -ErrorAction Stop)
        if ($site.Count -ne 1) { throw "Expected one site; received $($site.Count)." }
        Add-Result 'SCCM version' $SiteCode 'OK' 'Version and build reported by SMS_Site.' @($site | Select-Object SiteCode, SiteName, Version, BuildNumber)
    } catch {
        Add-Result 'SCCM version' $SiteCode 'Error' $_.Exception.Message
    }
    try {
        $start = $now.AddDays(-$BackupMaxAgeDays).ToUniversalTime().ToString('yyyyMMddHHmmss.000000+000')
        $messages = @(Get-CimInstance -ComputerName $SccmProvider -Namespace $namespace -ClassName SMS_StatusMessage -Filter "Component='SMS_SITE_BACKUP' AND SiteCode='$SiteCode' AND Time >= '$start'" -ErrorAction Stop |
            Sort-Object Time -Descending)
        $success = @($messages | Where-Object { $_.MessageID -eq 5035 } | Select-Object -First 1)
        $problems = @($messages | Where-Object { $_.Severity -in @(2147483648, 3221225472) -and ($success.Count -eq 0 -or $_.Time -gt $success[0].Time) })
        $status = if ($success.Count -eq 0 -or $problems.Count -gt 0) { 'Warning' } else { 'OK' }
        Add-Result 'SCCM backup' $SiteCode $status "Status messages within $BackupMaxAgeDays days: $($success.Count) success (5035), $($problems.Count) subsequent warnings/errors. This does not verify the current run or recoverability." @($messages | Select-Object Time, MessageID, Severity, MachineName, Component)
    } catch {
        Add-Result 'SCCM backup' $SiteCode 'Error' $_.Exception.Message
    }
}

if ($LogServers.Count -eq 0) {
    Add-Result 'Privileged logons' '-' 'NotConfigured' 'Provide -LogServers; security events are local to each queried computer.'
}
foreach ($server in $LogServers) {
    try {
        $events = @()
        try {
            $events = @(Get-WinEvent -ComputerName $server -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4672; StartTime = $now.AddDays(-$LogonDays) } -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -notmatch '^NoMatchingEventsFound') { throw }
        }
        $matches = @(
            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $fields = @{}
                foreach ($field in $xml.Event.EventData.Data) { $fields[$field.Name] = $field.'#text' }
                $sid = if ($event.Id -eq 4624) { $fields['TargetUserSid'] } else { $fields['SubjectUserSid'] }
                if ($event.Id -eq 4672 -or ($sid -and $privilegedSids.ContainsKey($sid))) {
                    [pscustomobject]@{
                        TimeCreated = $event.TimeCreated; EventId = $event.Id; SID = $sid
                        Account = if ($event.Id -eq 4624) { "$($fields['TargetDomainName'])\$($fields['TargetUserName'])" } else { "$($fields['SubjectDomainName'])\$($fields['SubjectUserName'])" }
                        LogonId = if ($event.Id -eq 4624) { $fields['TargetLogonId'] } else { $fields['SubjectLogonId'] }
                        LogonType = $fields['LogonType']; IpAddress = $fields['IpAddress']; Privileges = $fields['PrivilegeList']
                    }
                }
            }
        )
        $status = if ($membershipComplete) { 'OK' } else { 'Partial' }
        Add-Result 'Privileged logons' $server $status "Events since $($now.AddDays(-$LogonDays)): 4624 for resolved group members and all 4672 events. Audit policy, retention and current membership limit coverage." $matches
    } catch {
        Add-Result 'Privileged logons' $server 'Error' $_.Exception.Message
    }
}

$results.ToArray()

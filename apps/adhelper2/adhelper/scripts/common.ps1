Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Read-InputJson {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { return [pscustomobject]@{} }
    return $raw | ConvertFrom-Json
}

function Write-JsonResult {
    param(
        [bool]$Ok,
        [object]$Data = $null,
        [string]$Message = '',
        [string[]]$Warnings = @()
    )
    [pscustomobject]@{
        ok = $Ok
        data = $Data
        message = $Message
        warnings = @($Warnings)
    } | ConvertTo-Json -Depth 30 -Compress
}

function Escape-LdapValue {
    param([string]$Value)
    if ($null -eq $Value) { return '' }

    # RFC 4515. Не используем String.Replace(char, char): в Windows PowerShell 5.1
    # строка "\\00" ошибочно приводилась к System.Char и ломала любой поиск.
    $builder = [System.Text.StringBuilder]::new()
    foreach ($character in $Value.ToCharArray()) {
        switch ([int]$character) {
            0     { [void]$builder.Append('\00'); continue }
            40    { [void]$builder.Append('\28'); continue }
            41    { [void]$builder.Append('\29'); continue }
            42    { [void]$builder.Append('\2a'); continue }
            92    { [void]$builder.Append('\5c'); continue }
            default { [void]$builder.Append($character) }
        }
    }
    return $builder.ToString()
}

function Test-TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [int]$Port = 9389,
        [int]$TimeoutMs = 3000
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async)
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Get-DomainServer {
    param([object]$Domain)
    $base = [string]$Domain.server
    try {
        $pdc = (Get-ADDomain -Server $base -ErrorAction Stop).PDCEmulator
        if ($pdc) { return [string]$pdc }
    } catch { }
    return $base
}

function Get-IsFired {
    param([string]$Dn, [string]$FiredOu)
    if ([string]::IsNullOrWhiteSpace($Dn) -or [string]::IsNullOrWhiteSpace($FiredOu)) { return $false }
    $parent = ($Dn -split ',', 2)[1]
    return $parent.EndsWith($FiredOu, [System.StringComparison]::OrdinalIgnoreCase)
}


function Get-OffboardingClearAttributes {
    param([object]$Domain)
    $attributes = @(
        'title','department','company','physicalDeliveryOfficeName','telephoneNumber','mobile','mail',
        'streetAddress','l','st','postalCode','postOfficeBox','co','manager','description','info'
    )
    if ([string]$Domain.profile -eq 'omg') {
        $attributes += @(
            'facsimileTelephoneNumber','homePhone','ipPhone','pager','wWWHomePage',
            'otherTelephone','otherMobile','otherHomePhone','otherPager','division','section','otpMobile'
        )
        1..15 | ForEach-Object { $attributes += "extensionAttribute$_" }
    }
    return @($attributes)
}

function Convert-AdUserRecord {
    param([object]$User, [object]$Domain, [string]$Server)
    $managerName = ''
    $managerDn = [string]$User.Manager
    if ($managerDn) {
        try { $managerName = [string](Get-ADUser -Server $Server -Identity $managerDn -Properties DisplayName).DisplayName } catch { }
    }
    $otpMobile = ''
    try { $otpMobile = [string]$User.otpMobile } catch { }
    $division = ''
    try { $division = [string]$User.division } catch { }
    $section = ''
    try { $section = [string]$User.section } catch { }
    return [pscustomobject]@{
        domain = [string]$Domain.name
        displayName = [string]$User.DisplayName
        sam = [string]$User.SamAccountName
        upn = [string]$User.UserPrincipalName
        dn = [string]$User.DistinguishedName
        guid = if ($User.ObjectGUID) { $User.ObjectGUID.ToString() } else { '' }
        enabled = [bool]$User.Enabled
        mail = [string]$User.mail
        title = [string]$User.title
        department = [string]$User.department
        division = $division
        section = $section
        office = [string]$User.physicalDeliveryOfficeName
        telephoneNumber = [string]$User.telephoneNumber
        mobile = [string]$User.mobile
        otpMobile = $otpMobile
        managerName = $managerName
        managerDn = $managerDn
        streetAddress = [string]$User.streetAddress
        description = [string]$User.description
        isFired = Get-IsFired -Dn ([string]$User.DistinguishedName) -FiredOu ([string]$Domain.fired_ou_dn)
        memberOf = @($User.memberOf)
    }
}

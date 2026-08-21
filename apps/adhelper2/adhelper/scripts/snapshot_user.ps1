. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $server = Get-DomainServer $domain
    $samRaw = [string]$inputData.sam
    $sam = Escape-LdapValue $samRaw
    $guidRaw = ''
    try { $guidRaw = [string]$inputData.guid } catch { }

    # Единый список с offboard_user.ps1: всё, что процедура может очистить,
    # обязательно попадает в recovery-снимок до первого изменения.
    $clearAttrs = @(Get-OffboardingClearAttributes -Domain $domain)
    $identityProps = @(
        'ObjectGUID','DistinguishedName','Enabled','GivenName','sn','DisplayName',
        'SamAccountName','UserPrincipalName','c','memberOf'
    )
    $props = @($identityProps + $clearAttrs | Select-Object -Unique)

    $u = $null
    if (-not [string]::IsNullOrWhiteSpace($guidRaw)) {
        try { $u = Get-ADUser -Server $server -Identity ([guid]$guidRaw) -Properties $props -ErrorAction Stop } catch { }
    }
    if ($null -eq $u) {
        $users = @(Get-ADUser -Server $server -LDAPFilter "(sAMAccountName=$sam)" -SearchBase ([string]$domain.search_base) -Properties $props -ErrorAction SilentlyContinue)
        if ($users.Count -eq 0) { Write-JsonResult -Ok $true -Data $null; exit 0 }
        if ($users.Count -ne 1) { throw "По логину '$samRaw' найдено пользователей: $($users.Count)" }
        $u = $users[0]
    }

    $attributes = [ordered]@{}
    foreach ($name in $props) {
        try { $attributes[$name] = $u.$name } catch { $attributes[$name] = $null }
    }

    $data = [pscustomobject]@{
        domain = [string]$domain.name
        server = $server
        guid = $u.ObjectGUID.ToString()
        dn = [string]$u.DistinguishedName
        enabled = [bool]$u.Enabled
        displayName = [string]$u.DisplayName
        sam = [string]$u.SamAccountName
        attributes = $attributes
        clear_attributes = @($clearAttrs)
        target_fired_ou_dn = [string]$domain.fired_ou_dn
        domain_profile = [string]$domain.profile
        captured_at = (Get-Date).ToString('o')
    }
    Write-JsonResult -Ok $true -Data $data
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

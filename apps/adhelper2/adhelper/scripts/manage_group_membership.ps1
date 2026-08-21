. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $server = Get-DomainServer $domain
    $userIdentity = [string]$inputData.user_identity
    $expectedSam = [string]$inputData.expected_sam
    $groupIdentity = [string]$inputData.group_identity
    $action = ([string]$inputData.action).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($userIdentity) -or [string]::IsNullOrWhiteSpace($groupIdentity)) {
        throw "Не указан пользователь или группа"
    }
    if ($action -notin @('check','add')) {
        throw "Поддерживаются только операции check и add"
    }

    $user = Get-ADUser -Server $server -Identity $userIdentity -Properties MemberOf,ObjectGUID,SamAccountName,DistinguishedName -ErrorAction Stop
    if ($expectedSam -and ([string]$user.SamAccountName -ne $expectedSam)) {
        throw "Логин найденного пользователя не совпадает с выбранным: $($user.SamAccountName)"
    }
    $searchBase = [string]$domain.search_base
    if ($searchBase -and -not ([string]$user.DistinguishedName).EndsWith(',' + $searchBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Пользователь находится вне SearchBase выбранного домена"
    }

    $group = Get-ADGroup -Server $server -Identity $groupIdentity -Properties SamAccountName,DistinguishedName -ErrorAction Stop
    $groupBase = [string]$domain.group_search_base
    if ([string]::IsNullOrWhiteSpace($groupBase)) {
        throw "OU групп доступа не настроен"
    }
    if (-not ([string]$group.DistinguishedName).EndsWith(',' + $groupBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Выбранная группа находится вне настроенного OU групп доступа"
    }

    $alreadyMember = @($user.MemberOf) -contains [string]$group.DistinguishedName
    if ($action -eq 'check' -or $alreadyMember) {
        Write-JsonResult -Ok $true -Data ([pscustomobject]@{
            changed = $false
            already_member = [bool]$alreadyMember
            verified = [bool]$alreadyMember
            user_sam = [string]$user.SamAccountName
            user_dn = [string]$user.DistinguishedName
            group_sam = [string]$group.SamAccountName
            group_dn = [string]$group.DistinguishedName
            server = $server
        })
        exit 0
    }

    Add-ADGroupMember -Server $server -Identity $group.DistinguishedName -Members $user.DistinguishedName -Confirm:$false -ErrorAction Stop
    $verifiedUser = Get-ADUser -Server $server -Identity $user.ObjectGUID -Properties MemberOf -ErrorAction Stop
    $verified = @($verifiedUser.MemberOf) -contains [string]$group.DistinguishedName
    if (-not $verified) {
        throw "AD не подтвердил членство пользователя в группе после добавления"
    }
    Write-JsonResult -Ok $true -Data ([pscustomobject]@{
        changed = $true
        already_member = $false
        verified = $true
        user_sam = [string]$user.SamAccountName
        user_dn = [string]$user.DistinguishedName
        group_sam = [string]$group.SamAccountName
        group_dn = [string]$group.DistinguishedName
        server = $server
    })
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

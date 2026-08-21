. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $server = Get-DomainServer $domain
    $sam = [string]$inputData.sam
    $snapshot = $inputData.snapshot
    $targetOu = [string]$domain.fired_ou_dn
    $dryRun = [bool]$inputData.dry_run
    $phase = [string]$inputData.phase
    if ([string]::IsNullOrWhiteSpace($phase)) { $phase = 'all' }

    $clearAttrs = @(Get-OffboardingClearAttributes -Domain $domain)
    # Windows PowerShell 5.1 может падать с «Типы аргумента не совпадают»,
    # если generic List[T] оборачивать в @(...). Списки оставляем мутабельными,
    # но при сериализации всегда вызываем .ToArray().
    $warnings = New-Object System.Collections.Generic.List[string]
    $steps = New-Object System.Collections.Generic.List[object]

    function Test-HasAttributeValue {
        param([object]$Value)
        if ($null -eq $Value) { return $false }
        if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace([string]$Value) }
        if ($Value -is [System.Collections.IEnumerable]) { return @($Value).Count -gt 0 }
        return $true
    }

    function Get-TargetUser {
        $properties = @($clearAttrs + @('ObjectGUID','DistinguishedName','Enabled','GivenName','sn','DisplayName','SamAccountName') | Select-Object -Unique)
        $user = $null
        $snapshotGuid = [string]$snapshot.guid
        if (-not [string]::IsNullOrWhiteSpace($snapshotGuid)) {
            try { $user = Get-ADUser -Server $server -Identity ([guid]$snapshotGuid) -Properties $properties -ErrorAction Stop } catch { }
        }
        if ($null -eq $user) {
            $samEsc = Escape-LdapValue $sam
            $users = @(Get-ADUser -Server $server -LDAPFilter "(sAMAccountName=$samEsc)" -SearchBase ([string]$domain.search_base) -Properties $properties -ErrorAction SilentlyContinue)
            if ($users.Count -ne 1) {
                throw "Пользователь '$sam' не найден однозначно в домене $([string]$domain.name). Найдено: $($users.Count)"
            }
            $user = $users[0]
        }
        if (-not [string]::IsNullOrWhiteSpace($snapshotGuid) -and $user.ObjectGUID.ToString() -ne $snapshotGuid) {
            throw "GUID пользователя изменился после recovery-снимка. Операция остановлена до внесения изменений"
        }
        if (-not ([string]$user.SamAccountName).Equals($sam, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Логин найденного объекта не совпадает с подтверждённым логином '$sam'"
        }
        return $user
    }

    function Assert-TargetOu {
        if ([string]::IsNullOrWhiteSpace($targetOu)) {
            throw "В настройках домена '$([string]$domain.label)' не задано поле 'OU уволенных'"
        }
        try {
            Get-ADOrganizationalUnit -Server $server -Identity $targetOu -ErrorAction Stop | Out-Null
        } catch {
            throw "OU уволенных недоступен в домене '$([string]$domain.label)': $targetOu. $($_.Exception.Message)"
        }
    }

    function Invoke-ValidatePhase {
        $user = Get-TargetUser
        Assert-TargetOu
        $populated = New-Object System.Collections.Generic.List[string]
        foreach ($attribute in $clearAttrs) {
            try {
                if (Test-HasAttributeValue -Value $user.$attribute) { $populated.Add([string]$attribute) }
            } catch { }
        }
        $status = if ($dryRun) { 'simulated' } else { 'success' }
        return [pscustomobject]@{
            key = 'identity'
            status = $status
            message = "Пользователь и OU уволенных проверены"
            dn = [string]$user.DistinguishedName
            target_ou = $targetOu
            clear_attributes = @($clearAttrs)
            populated_attributes = $populated.ToArray()
        }
    }

    function Invoke-ClearPhase {
        $user = Get-TargetUser
        $toClear = New-Object System.Collections.Generic.List[string]
        foreach ($attribute in $clearAttrs) {
            try {
                if (Test-HasAttributeValue -Value $user.$attribute) { $toClear.Add([string]$attribute) }
            } catch { }
        }
        if ($dryRun) {
            return [pscustomobject]@{
                key = 'clear'; status = 'simulated'
                message = "Будут очищены заполненные атрибуты: $($toClear.Count)"
                cleared = @(); skipped_empty = @($clearAttrs | Where-Object { $_ -notin $toClear.ToArray() }); failed = @()
            }
        }
        $cleared = New-Object System.Collections.Generic.List[string]
        $failed = New-Object System.Collections.Generic.List[string]
        foreach ($attribute in $toClear) {
            try {
                Set-ADUser -Server $server -Identity $user.ObjectGUID -Clear $attribute -ErrorAction Stop
                $cleared.Add([string]$attribute)
            } catch {
                $failed.Add([string]$attribute)
                $warnings.Add(("Не очищен {0}: {1}" -f $attribute, $_.Exception.Message))
            }
        }
        # ФИО и логин не входят в список очистки. Дополнительно проверяем, что объект тот же.
        $after = Get-TargetUser
        $clearStatus = if ($failed.Count) { 'warning' } else { 'success' }
        $clearMessage = if ($failed.Count) {
            "Очищено: $($cleared.Count), не очищено: $($failed.Count)"
        } else {
            "Очищено заполненных атрибутов: $($cleared.Count)"
        }
        return [pscustomobject]@{
            key = 'clear'; status = $clearStatus; message = $clearMessage
            cleared = $cleared.ToArray(); skipped_empty = @($clearAttrs | Where-Object { $_ -notin $toClear.ToArray() }); failed = $failed.ToArray()
            dn = [string]$after.DistinguishedName
        }
    }

    function Invoke-DisablePhase {
        $user = Get-TargetUser
        if ($dryRun) {
            return [pscustomobject]@{ key='disable'; status='simulated'; message='Учётная запись будет отключена' }
        }
        if (-not [bool]$user.Enabled) {
            return [pscustomobject]@{ key='disable'; status='skipped'; message='Учётная запись уже была отключена' }
        }
        Disable-ADAccount -Server $server -Identity $user.ObjectGUID -ErrorAction Stop
        $enabled = [bool](Get-ADUser -Server $server -Identity $user.ObjectGUID -Properties Enabled -ErrorAction Stop).Enabled
        if ($enabled) { throw 'После Disable-ADAccount учётная запись осталась включённой' }
        return [pscustomobject]@{ key='disable'; status='success'; message='Учётная запись отключена' }
    }

    function Invoke-MovePhase {
        $user = Get-TargetUser
        Assert-TargetOu
        $currentDn = [string]$user.DistinguishedName
        $parent = ($currentDn -split ',', 2)[1]
        if ($dryRun) {
            return [pscustomobject]@{ key='move'; status='simulated'; message="Пользователь будет перемещён в $targetOu"; dn=$currentDn }
        }
        if ($parent.Equals($targetOu, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [pscustomobject]@{ key='move'; status='skipped'; message='Пользователь уже находится в OU уволенных'; dn=$currentDn }
        }
        Move-ADObject -Server $server -Identity $user.ObjectGUID -TargetPath $targetOu -ErrorAction Stop
        $after = Get-ADUser -Server $server -Identity $user.ObjectGUID -Properties @('DistinguishedName','Enabled') -ErrorAction Stop
        $afterParent = ([string]$after.DistinguishedName -split ',', 2)[1]
        if (-not $afterParent.Equals($targetOu, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Объект не оказался в заданном OU после Move-ADObject. Текущий DN: $([string]$after.DistinguishedName)"
        }
        return [pscustomobject]@{ key='move'; status='success'; message='Пользователь перемещён в OU уволенных'; dn=[string]$after.DistinguishedName }
    }

    switch ($phase.ToLowerInvariant()) {
        'validate' { $steps.Add((Invoke-ValidatePhase)) }
        'clear'    { $steps.Add((Invoke-ClearPhase)) }
        'disable'  { $steps.Add((Invoke-DisablePhase)) }
        'move'     { $steps.Add((Invoke-MovePhase)) }
        'all' {
            $steps.Add((Invoke-ValidatePhase))
            $steps.Add((Invoke-ClearPhase))
            $steps.Add((Invoke-DisablePhase))
            $steps.Add((Invoke-MovePhase))
        }
        default { throw "Неизвестная фаза увольнения: $phase" }
    }

    $lastUser = Get-TargetUser
    Write-JsonResult -Ok $true -Data ([pscustomobject]@{
        phase = $phase
        simulated = $dryRun
        server = $server
        target_ou = $targetOu
        dn_before = [string]$snapshot.dn
        dn_after = [string]$lastUser.DistinguishedName
        enabled_after = [bool]$lastUser.Enabled
        clear_attributes = @($clearAttrs)
        steps = $steps.ToArray()
        warnings = $warnings.ToArray()
    }) -Warnings $warnings.ToArray()
} catch {
    $message = [string]$_.Exception.Message
    if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) {
        $lineText = ([string]$_.InvocationInfo.Line).Trim()
        $message = "{0} [строка {1}: {2}]" -f $message, $_.InvocationInfo.ScriptLineNumber, $lineText
    }
    Write-JsonResult -Ok $false -Message $message
    exit 1
}

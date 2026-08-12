. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $snapshot = $inputData.snapshot
    $server = Get-DomainServer $domain
    $dryRun = [bool]$inputData.dry_run
    $phase = [string]$inputData.phase
    if ([string]::IsNullOrWhiteSpace($phase)) { $phase = 'all' }

    if ($null -eq $snapshot) { throw 'Recovery-снимок не передан' }
    if ($null -eq $snapshot.attributes) { throw 'Recovery-снимок не содержит attributes' }

    $snapshotGuid = [string]$snapshot.guid
    if ([string]::IsNullOrWhiteSpace($snapshotGuid)) {
        try { $snapshotGuid = [string]$snapshot.attributes.ObjectGUID } catch { }
    }
    $sam = [string]$snapshot.sam
    if ([string]::IsNullOrWhiteSpace($sam)) {
        try { $sam = [string]$snapshot.attributes.SamAccountName } catch { }
    }
    $originalDn = [string]$snapshot.dn
    if ([string]::IsNullOrWhiteSpace($originalDn)) {
        try { $originalDn = [string]$snapshot.attributes.DistinguishedName } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($snapshotGuid) -or [string]::IsNullOrWhiteSpace($sam) -or [string]::IsNullOrWhiteSpace($originalDn)) {
        throw 'Recovery-снимок не содержит обязательные guid, sam или исходный DN'
    }

    $snapshotProfileProperty = $snapshot.PSObject.Properties['domain_profile']
    if ($null -ne $snapshotProfileProperty -and -not [string]::IsNullOrWhiteSpace([string]$snapshotProfileProperty.Value)) {
        $snapshotProfile = [string]$snapshotProfileProperty.Value
        if (-not $snapshotProfile.Equals([string]$domain.profile, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Профиль домена в recovery JSON '$snapshotProfile' не совпадает с текущей настройкой '$([string]$domain.profile)'"
        }
    }

    $originalEnabled = $true
    $enabledProperty = $snapshot.PSObject.Properties['enabled']
    if ($null -ne $enabledProperty) {
        $originalEnabled = [bool]$enabledProperty.Value
    } else {
        $attrEnabled = $snapshot.attributes.PSObject.Properties['Enabled']
        if ($null -eq $attrEnabled) { throw 'Recovery-снимок не содержит исходное состояние Enabled' }
        $originalEnabled = [bool]$attrEnabled.Value
    }

    function Get-ParentDn {
        param([Parameter(Mandatory = $true)][string]$Dn)
        $escaped = $false
        for ($i = 0; $i -lt $Dn.Length; $i++) {
            $ch = $Dn[$i]
            if ($escaped) { $escaped = $false; continue }
            if ($ch -eq '\') { $escaped = $true; continue }
            if ($ch -eq ',') { return $Dn.Substring($i + 1) }
        }
        throw "Не удалось определить родительский DN из '$Dn'"
    }

    function Test-DnEqual {
        param([string]$Left, [string]$Right)
        if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }
        return $Left.Equals($Right, [System.StringComparison]::OrdinalIgnoreCase)
    }

    function Test-HasAttributeValue {
        param([object]$Value)
        if ($null -eq $Value) { return $false }
        if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace([string]$Value) }
        if ($Value -is [System.Collections.IEnumerable]) { return @($Value).Count -gt 0 }
        return $true
    }

    function Convert-ComparableValues {
        param([object]$Value)
        if ($null -eq $Value) { return @() }
        if ($Value -is [string]) {
            if ([string]::IsNullOrWhiteSpace([string]$Value)) { return @() }
            return @([string]$Value)
        }
        if ($Value -is [System.Collections.IEnumerable]) {
            return @($Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
        }
        return @([string]$Value)
    }

    function Test-ValuesEqual {
        param([object]$Left, [object]$Right)
        $a = @(Convert-ComparableValues -Value $Left)
        $b = @(Convert-ComparableValues -Value $Right)
        if ($a.Count -ne $b.Count) { return $false }
        for ($i = 0; $i -lt $a.Count; $i++) {
            if (-not ([string]$a[$i]).Equals([string]$b[$i], [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
        }
        return $true
    }

    function Get-SnapshotAttribute {
        param([string]$Name)
        $property = $snapshot.attributes.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }

    $allowedAttrs = @(Get-OffboardingClearAttributes -Domain $domain)
    $snapshotPropertyNames = @($snapshot.attributes.PSObject.Properties | ForEach-Object { [string]$_.Name })
    $declaredClearAttrs = @()
    $clearProperty = $snapshot.PSObject.Properties['clear_attributes']
    if ($null -ne $clearProperty -and $null -ne $clearProperty.Value) {
        $declaredClearAttrs = @($clearProperty.Value | ForEach-Object { [string]$_ })
    }

    # Never trust arbitrary attribute names from an editable JSON file. Restore only attributes
    # that the current ADHelper offboarding policy is allowed to clear and that are present in the snapshot.
    $restoreAttrs = @()
    foreach ($attribute in $allowedAttrs) {
        if ($snapshotPropertyNames -notcontains $attribute) { continue }
        if ($declaredClearAttrs.Count -gt 0 -and $declaredClearAttrs -notcontains $attribute) { continue }
        $restoreAttrs += [string]$attribute
    }

    $originalParent = Get-ParentDn -Dn $originalDn
    $configuredFiredOu = [string]$domain.fired_ou_dn
    $snapshotFiredOu = ''
    try { $snapshotFiredOu = [string]$snapshot.target_fired_ou_dn } catch { }
    $rollbackAllowedParent = ''
    try {
        $rollbackAllowedDn = [string]$snapshot.rollback_allowed_current_dn
        if (-not [string]::IsNullOrWhiteSpace($rollbackAllowedDn)) { $rollbackAllowedParent = Get-ParentDn -Dn $rollbackAllowedDn }
    } catch { }

    function Get-TargetUser {
        $properties = @($restoreAttrs + @('ObjectGUID','DistinguishedName','Enabled','SamAccountName','DisplayName') | Select-Object -Unique)
        $user = $null
        try { $user = Get-ADUser -Server $server -Identity ([guid]$snapshotGuid) -Properties $properties -ErrorAction Stop } catch { }
        if ($null -eq $user) {
            try { $user = Get-ADUser -Server $server -Identity $sam -Properties $properties -ErrorAction Stop } catch { }
        }
        if ($null -eq $user) { throw "Пользователь '$sam' из recovery JSON не найден в домене $([string]$domain.label)" }
        if ($user.ObjectGUID.ToString() -ne $snapshotGuid) {
            throw "GUID текущей учётной записи не совпадает с recovery JSON. Ожидался $snapshotGuid, найден $($user.ObjectGUID)"
        }
        if (-not ([string]$user.SamAccountName).Equals($sam, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Логин текущего объекта '$([string]$user.SamAccountName)' не совпадает с recovery JSON '$sam'"
        }
        return $user
    }

    function Assert-OriginalOu {
        try {
            Get-ADObject -Server $server -Identity $originalParent -ErrorAction Stop | Out-Null
        } catch {
            throw "Исходный OU/контейнер из recovery JSON недоступен: $originalParent. $($_.Exception.Message)"
        }
    }

    function Assert-CurrentLocation {
        param([object]$User)
        $currentParent = Get-ParentDn -Dn ([string]$User.DistinguishedName)
        $allowed = (Test-DnEqual $currentParent $originalParent)
        if (-not $allowed -and -not [string]::IsNullOrWhiteSpace($configuredFiredOu)) {
            $allowed = Test-DnEqual $currentParent $configuredFiredOu
        }
        if (-not $allowed -and -not [string]::IsNullOrWhiteSpace($snapshotFiredOu)) {
            $allowed = Test-DnEqual $currentParent $snapshotFiredOu
        }
        if (-not $allowed -and -not [string]::IsNullOrWhiteSpace($rollbackAllowedParent)) {
            $allowed = Test-DnEqual $currentParent $rollbackAllowedParent
        }
        if (-not $allowed) {
            throw "Текущий OU пользователя не совпадает ни с OU уволенных, ни с исходным OU. Текущий: $currentParent"
        }
        return $currentParent
    }

    function Invoke-ValidatePhase {
        $user = Get-TargetUser
        Assert-OriginalOu
        $currentParent = Assert-CurrentLocation -User $user
        $toRestore = @()
        foreach ($attribute in $restoreAttrs) {
            $desired = Get-SnapshotAttribute -Name $attribute
            $current = $user.$attribute
            if (-not (Test-ValuesEqual -Left $current -Right $desired)) { $toRestore += $attribute }
        }
        $enabledChange = ([bool]$user.Enabled -ne $originalEnabled)
        $moveNeeded = -not (Test-DnEqual $currentParent $originalParent)
        $status = if ($dryRun) { 'simulated' } else { 'success' }
        return [pscustomobject]@{
            key = 'validate'
            status = $status
            message = "Recovery JSON соответствует текущему объекту; восстановление безопасно для запуска"
            sam = $sam
            guid = $snapshotGuid
            current_dn = [string]$user.DistinguishedName
            original_dn = $originalDn
            original_parent = $originalParent
            current_parent = $currentParent
            attributes_in_snapshot = $restoreAttrs.Count
            attributes_to_restore = $toRestore.Count
            attributes_to_restore_names = @($toRestore)
            move_needed = $moveNeeded
            original_enabled = $originalEnabled
            enabled_change_needed = $enabledChange
        }
    }

    function Invoke-AttributesPhase {
        $user = Get-TargetUser
        Assert-OriginalOu
        [void](Assert-CurrentLocation -User $user)
        $toRestore = @()
        foreach ($attribute in $restoreAttrs) {
            $desired = Get-SnapshotAttribute -Name $attribute
            if (-not (Test-ValuesEqual -Left $user.$attribute -Right $desired)) { $toRestore += $attribute }
        }
        if ($dryRun) {
            return [pscustomobject]@{
                key='attributes'; status='simulated'
                message="Будут восстановлены атрибуты: $($toRestore.Count)"
                restored=@(); unchanged=@($restoreAttrs | Where-Object { $_ -notin $toRestore }); failed=@()
            }
        }

        $restored = @()
        $failed = @()
        $warnings = @()
        foreach ($attribute in $toRestore) {
            $desired = Get-SnapshotAttribute -Name $attribute
            try {
                if (Test-HasAttributeValue -Value $desired) {
                    $replace = @{}
                    $replace[$attribute] = $desired
                    Set-ADUser -Server $server -Identity $user.ObjectGUID -Replace $replace -ErrorAction Stop
                } else {
                    Set-ADUser -Server $server -Identity $user.ObjectGUID -Clear $attribute -ErrorAction Stop
                }
                $restored += $attribute
            } catch {
                $failed += $attribute
                $warnings += ("Не восстановлен {0}: {1}" -f $attribute, $_.Exception.Message)
            }
        }

        $after = Get-TargetUser
        $verificationFailed = @()
        foreach ($attribute in $restored) {
            $desired = Get-SnapshotAttribute -Name $attribute
            if (-not (Test-ValuesEqual -Left $after.$attribute -Right $desired)) {
                $verificationFailed += $attribute
            }
        }
        foreach ($attribute in $verificationFailed) {
            if ($failed -notcontains $attribute) { $failed += $attribute }
            $warnings += "После записи значение '$attribute' не совпало с recovery JSON"
        }
        $restored = @($restored | Where-Object { $_ -notin $failed })
        $status = if ($failed.Count -gt 0) { 'failed' } else { 'success' }
        $message = if ($failed.Count -gt 0) {
            "Восстановлено: $($restored.Count), ошибок: $($failed.Count). Перемещение и включение заблокированы"
        } else {
            "Восстановлено атрибутов: $($restored.Count); без изменений: $($restoreAttrs.Count - $toRestore.Count)"
        }
        return [pscustomobject]@{
            key='attributes'; status=$status; message=$message
            restored=@($restored); unchanged=@($restoreAttrs | Where-Object { $_ -notin $toRestore }); failed=@($failed); warnings=@($warnings)
        }
    }

    function Invoke-MovePhase {
        $user = Get-TargetUser
        Assert-OriginalOu
        $currentParent = Assert-CurrentLocation -User $user
        if (Test-DnEqual $currentParent $originalParent) {
            return [pscustomobject]@{ key='move'; status='skipped'; message='Пользователь уже находится в исходном OU'; dn=[string]$user.DistinguishedName }
        }
        if ($dryRun) {
            return [pscustomobject]@{ key='move'; status='simulated'; message="Пользователь будет возвращён в $originalParent"; dn=[string]$user.DistinguishedName }
        }
        Move-ADObject -Server $server -Identity $user.ObjectGUID -TargetPath $originalParent -ErrorAction Stop
        $after = Get-TargetUser
        $afterParent = Get-ParentDn -Dn ([string]$after.DistinguishedName)
        if (-not (Test-DnEqual $afterParent $originalParent)) {
            throw "После Move-ADObject пользователь не оказался в исходном OU. Текущий DN: $([string]$after.DistinguishedName)"
        }
        return [pscustomobject]@{ key='move'; status='success'; message='Пользователь возвращён в исходный OU'; dn=[string]$after.DistinguishedName }
    }

    function Invoke-EnablePhase {
        $user = Get-TargetUser
        if ([bool]$user.Enabled -eq $originalEnabled) {
            $state = if ($originalEnabled) { 'Enabled=True' } else { 'Enabled=False' }
            return [pscustomobject]@{ key='enable'; status='skipped'; message="Состояние уже соответствует recovery JSON: $state" }
        }
        if ($dryRun) {
            $action = if ($originalEnabled) { 'включена' } else { 'отключена' }
            return [pscustomobject]@{ key='enable'; status='simulated'; message="Учётная запись будет $action" }
        }
        if ($originalEnabled) {
            Enable-ADAccount -Server $server -Identity $user.ObjectGUID -ErrorAction Stop
        } else {
            Disable-ADAccount -Server $server -Identity $user.ObjectGUID -ErrorAction Stop
        }
        $afterEnabled = [bool](Get-ADUser -Server $server -Identity $user.ObjectGUID -Properties Enabled -ErrorAction Stop).Enabled
        if ($afterEnabled -ne $originalEnabled) {
            throw "После изменения Enabled не совпадает с recovery JSON. Ожидалось: $originalEnabled, получено: $afterEnabled"
        }
        $state = if ($afterEnabled) { 'Enabled=True' } else { 'Enabled=False' }
        return [pscustomobject]@{ key='enable'; status='success'; message="Исходное состояние восстановлено: $state" }
    }

    $steps = @()
    $warnings = @()
    switch ($phase.ToLowerInvariant()) {
        'validate' { $steps += Invoke-ValidatePhase }
        'attributes' {
            $result = Invoke-AttributesPhase
            $steps += $result
            if ($null -ne $result.PSObject.Properties['warnings']) { $warnings += @($result.warnings) }
        }
        'move' { $steps += Invoke-MovePhase }
        'enable' { $steps += Invoke-EnablePhase }
        'all' {
            $steps += Invoke-ValidatePhase
            $attributeResult = Invoke-AttributesPhase
            $steps += $attributeResult
            if ($null -ne $attributeResult.PSObject.Properties['warnings']) { $warnings += @($attributeResult.warnings) }
            if ([string]$attributeResult.status -eq 'failed') {
                Write-JsonResult -Ok $true -Data ([pscustomobject]@{ steps=@($steps); warnings=@($warnings) }) -Warnings @($warnings)
                exit 0
            }
            $steps += Invoke-MovePhase
            $steps += Invoke-EnablePhase
        }
        default { throw "Неизвестная фаза восстановления: $phase" }
    }

    Write-JsonResult -Ok $true -Data ([pscustomobject]@{ steps=@($steps); warnings=@($warnings) }) -Warnings @($warnings)
} catch {
    $line = ''
    try { $line = " Строка $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" } catch { }
    Write-JsonResult -Ok $false -Message ($_.Exception.Message + $line)
    exit 1
}

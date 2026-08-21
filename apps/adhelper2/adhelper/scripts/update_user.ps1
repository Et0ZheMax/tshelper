. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $changes = $inputData.changes
    $server = Get-DomainServer $domain
    $identity = [string]$inputData.identity
    $user = Get-ADUser -Server $server -Identity $identity -Properties @('DistinguishedName','ObjectGUID') -ErrorAction Stop

    $setParams = @{ Server=$server; Identity=$user.ObjectGUID; ErrorAction='Stop' }
    $clear = New-Object System.Collections.Generic.List[string]
    $replace = @{}
    $allowedMap = @{
        title='Title'; department='Department'; office='Office'; street_address='StreetAddress';
        description='Description'; mail='EmailAddress'; mobile='MobilePhone'; telephone='OfficePhone';
        division='Division'
    }
    foreach ($property in $allowedMap.Keys) {
        if ($changes.PSObject.Properties.Name -contains $property) {
            $value = [string]$changes.$property
            if ([string]::IsNullOrWhiteSpace($value)) {
                $ldapMap = @{ title='title'; department='department'; office='physicalDeliveryOfficeName'; street_address='streetAddress'; description='description'; mail='mail'; mobile='mobile'; telephone='telephoneNumber'; division='division' }
                $clear.Add($ldapMap[$property])
            } else {
                $setParams[$allowedMap[$property]] = $value
            }
        }
    }
    if ($changes.PSObject.Properties.Name -contains 'section') {
        $value = [string]$changes.section
        if ($value) { $replace.section = $value } else { $clear.Add('section') }
    }
    if ($changes.PSObject.Properties.Name -contains 'otp_mobile') {
        $value = [string]$changes.otp_mobile
        if ($value) { $replace.otpMobile = $value } else { $clear.Add('otpMobile') }
    }
    if ($changes.PSObject.Properties.Name -contains 'manager_dn') {
        $managerDn = [string]$changes.manager_dn
        if ($managerDn) { $setParams.Manager = $managerDn } else { $clear.Add('manager') }
    }
    if ($setParams.Keys.Count -gt 3) { Set-ADUser @setParams }
    if ($replace.Count -gt 0) { Set-ADUser -Server $server -Identity $user.ObjectGUID -Replace $replace -ErrorAction Stop }
    if ($clear.Count -gt 0) { Set-ADUser -Server $server -Identity $user.ObjectGUID -Clear @($clear | Select-Object -Unique) -ErrorAction Stop }

    if ($changes.PSObject.Properties.Name -contains 'target_ou' -and [string]$changes.target_ou) {
        $target = [string]$changes.target_ou
        Get-ADOrganizationalUnit -Server $server -Identity $target -ErrorAction Stop | Out-Null
        $current = (Get-ADUser -Server $server -Identity $user.ObjectGUID).DistinguishedName
        $parent = ($current -split ',',2)[1]
        if (-not $parent.Equals($target, [System.StringComparison]::OrdinalIgnoreCase)) {
            Move-ADObject -Server $server -Identity $user.ObjectGUID -TargetPath $target -ErrorAction Stop
        }
    }

    $props = @('DisplayName','SamAccountName','UserPrincipalName','DistinguishedName','ObjectGUID','Enabled','mail','department','title','physicalDeliveryOfficeName','telephoneNumber','mobile','streetAddress','description','manager','memberOf')
    if ([string]$domain.profile -eq 'omg') { $props += 'division','section','otpMobile' }
    $updated = Get-ADUser -Server $server -Identity $user.ObjectGUID -Properties $props -ErrorAction Stop
    Write-JsonResult -Ok $true -Data (Convert-AdUserRecord -User $updated -Domain $domain -Server $server)
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

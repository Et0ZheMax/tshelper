. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $user = $inputData.user
    $server = Get-DomainServer $domain
    $targetOu = [string]$user.target_ou
    Get-ADOrganizationalUnit -Server $server -Identity $targetOu -ErrorAction Stop | Out-Null

    $samEsc = Escape-LdapValue ([string]$user.sam)
    $upnEsc = Escape-LdapValue ([string]$user.upn)
    $existing = Get-ADUser -Server $server -LDAPFilter "(|(sAMAccountName=$samEsc)(userPrincipalName=$upnEsc))" -SearchBase ([string]$domain.search_base) -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing) { throw "Пользователь с таким sAMAccountName или UPN уже существует: $($existing.DistinguishedName)" }

    $preview = [pscustomobject]@{ server=$server; target_ou=$targetOu; sam=[string]$user.sam; upn=[string]$user.upn; display_name=[string]$user.display_name }
    if ([bool]$inputData.dry_run) {
        Write-JsonResult -Ok $true -Data ([pscustomobject]@{ simulated=$true; preview=$preview })
        exit 0
    }

    $securePassword = ConvertTo-SecureString ([string]$user.password) -AsPlainText -Force
    $params = @{
        Server = $server
        Path = $targetOu
        Name = [string]$user.display_name
        DisplayName = [string]$user.display_name
        GivenName = [string]$user.first_name
        Surname = [string]$user.last_name
        SamAccountName = [string]$user.sam
        UserPrincipalName = [string]$user.upn
        AccountPassword = $securePassword
        Enabled = $true
        ChangePasswordAtLogon = [bool]$user.change_password_at_logon
        ErrorAction = 'Stop'
    }
    if ([string]$user.title) { $params.Title = [string]$user.title }
    if ([string]$user.department) { $params.Department = [string]$user.department }
    if ([string]$user.company) { $params.Company = [string]$user.company }
    if ([string]$user.office) { $params.Office = [string]$user.office }
    if ([string]$user.street_address) { $params.StreetAddress = [string]$user.street_address }
    if ([string]$user.description) { $params.Description = [string]$user.description }
    if ([string]$user.mail) { $params.EmailAddress = [string]$user.mail }
    if ([string]$user.mobile) { $params.MobilePhone = [string]$user.mobile }
    if ([string]$user.division) { $params.Division = [string]$user.division }
    $meta = $user.address_meta
    if ($meta) {
        if ([string]$meta.pobox) { $params.POBox = [string]$meta.pobox }
        if ([string]$meta.city) { $params.City = [string]$meta.city }
        if ([string]$meta.state) { $params.State = [string]$meta.state }
        if ([string]$meta.postal_code) { $params.PostalCode = [string]$meta.postal_code }
        if ([string]$meta.country) { $params.Country = [string]$meta.country }
    }
    $other = @{}
    if ([string]$user.otp_mobile) { $other.otpMobile = [string]$user.otp_mobile }
    if ([string]$user.section) { $other.section = [string]$user.section }
    if ($other.Count -gt 0) { $params.OtherAttributes = $other }

    New-ADUser @params
    if ([string]$user.manager_dn) {
        Set-ADUser -Server $server -Identity ([string]$user.sam) -Manager ([string]$user.manager_dn) -ErrorAction Stop
    }
    $props = @('DisplayName','SamAccountName','UserPrincipalName','DistinguishedName','ObjectGUID','Enabled','mail','department','title','physicalDeliveryOfficeName','telephoneNumber','mobile','streetAddress','description','manager','memberOf')
    if ([string]$domain.profile -eq 'omg') { $props += 'division','section','otpMobile' }
    $created = Get-ADUser -Server $server -Identity ([string]$user.sam) -Properties $props -ErrorAction Stop
    Write-JsonResult -Ok $true -Data (Convert-AdUserRecord -User $created -Domain $domain -Server $server)
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

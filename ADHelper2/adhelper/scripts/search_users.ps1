. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $query = [string]$inputData.query
    $q = Escape-LdapValue $query
    $digits = ($query -replace '\D', '')
    $all = @()
    foreach ($domain in @($inputData.domains)) {
        $parts = @("(displayName=*$q*)", "(sAMAccountName=*$q*)", "(userPrincipalName=*$q*)")
        if ($digits) {
            $d = Escape-LdapValue $digits
            $parts += "(telephoneNumber=*$d*)", "(mobile=*$d*)"
            if ([string]$domain.profile -eq 'omg') { $parts += "(otpMobile=*$d*)" }
        }
        $filter = '(|' + ($parts -join '') + ')'
        $server = Get-DomainServer $domain
        $props = @('DisplayName','SamAccountName','UserPrincipalName','DistinguishedName','ObjectGUID','Enabled','mail','department','title','physicalDeliveryOfficeName','telephoneNumber','mobile','streetAddress','description','manager','memberOf')
        if ([string]$domain.profile -eq 'omg') { $props += 'division','section','otpMobile' }
        $users = @(Get-ADUser -Server $server -LDAPFilter $filter -SearchBase ([string]$domain.search_base) -ResultSetSize 150 -Properties $props -ErrorAction SilentlyContinue)
        foreach ($user in $users) {
            $record = Convert-AdUserRecord -User $user -Domain $domain -Server $server
            if ([bool]$inputData.include_fired -or -not $record.isFired) { $all += $record }
        }
    }
    $sorted = @($all | Sort-Object -Property @("displayName","domain"))
    Write-JsonResult -Ok $true -Data $sorted
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

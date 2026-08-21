. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $server = Get-DomainServer $domain
    $q = Escape-LdapValue ([string]$inputData.query)
    $filter = "(|(displayName=*$q*)(sAMAccountName=*$q*))"
    $props = @('DisplayName','SamAccountName','UserPrincipalName','DistinguishedName','ObjectGUID','Enabled','department','title','mail','manager','memberOf')
    $items = @(Get-ADUser -Server $server -LDAPFilter $filter -SearchBase ([string]$domain.search_base) -ResultSetSize 30 -Properties $props | ForEach-Object {
        Convert-AdUserRecord -User $_ -Domain $domain -Server $server
    })
    Write-JsonResult -Ok $true -Data $items
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

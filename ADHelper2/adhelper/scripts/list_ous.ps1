. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $server = Get-DomainServer $domain
    $base = [string]$inputData.search_base
    $items = @(Get-ADOrganizationalUnit -Server $server -Filter * -SearchBase $base -Properties @('Name','DistinguishedName') | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ name=[string]$_.Name; dn=[string]$_.DistinguishedName }
    })
    Write-JsonResult -Ok $true -Data $items
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

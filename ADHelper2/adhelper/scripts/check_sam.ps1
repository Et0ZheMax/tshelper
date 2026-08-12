. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $sam = [string]$inputData.sam
    $escaped = Escape-LdapValue $sam
    $matches = @()
    foreach ($domain in @($inputData.domains)) {
        $server = Get-DomainServer $domain
        $user = Get-ADUser -Server $server -LDAPFilter "(sAMAccountName=$escaped)" -SearchBase ([string]$domain.search_base) -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($user) { $matches += [pscustomobject]@{ domain=[string]$domain.name; dn=[string]$user.DistinguishedName } }
    }
    Write-JsonResult -Ok $true -Data ([pscustomobject]@{ exists=($matches.Count -gt 0); matches=$matches })
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $domainName = [string]$domain.name
    $searchBase = [string]$domain.search_base
    $identity = [string]$inputData.identity
    $expectedSam = [string]$inputData.expected_sam
    $expectedGuid = [string]$inputData.expected_guid

    if ([string]::IsNullOrWhiteSpace($domainName)) { throw 'Domain name is missing' }
    if ([string]::IsNullOrWhiteSpace($searchBase)) { throw 'Domain SearchBase is missing' }
    if ([string]::IsNullOrWhiteSpace($identity)) { throw 'User identity is missing' }

    $server = Get-DomainServer $domain
    $user = Get-ADUser -Server $server -Identity $identity -Properties @(
        'DisplayName','SamAccountName','DistinguishedName','ObjectGUID'
    ) -ErrorAction Stop

    $actualDn = [string]$user.DistinguishedName
    $insideSearchBase = $actualDn.EndsWith("," + $searchBase, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $insideSearchBase) {
        throw "Selected user is outside SearchBase for domain '$domainName'"
    }

    $actualSam = [string]$user.SamAccountName
    if (-not [string]::IsNullOrWhiteSpace($expectedSam) -and
        -not $actualSam.Equals($expectedSam, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Selected user login does not match expected login '$expectedSam'"
    }

    $actualGuid = if ($user.ObjectGUID) { $user.ObjectGUID.ToString() } else { '' }
    if (-not [string]::IsNullOrWhiteSpace($expectedGuid) -and
        -not $actualGuid.Equals($expectedGuid, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Selected user GUID does not match the search result'
    }

    $deleted = [pscustomobject]@{
        domain = $domainName
        sam = $actualSam
        guid = $actualGuid
        display_name = [string]$user.DisplayName
        dn = $actualDn
    }
    Remove-ADUser -Server $server -Identity $user.ObjectGUID -Confirm:$false -ErrorAction Stop
    Write-JsonResult -Ok $true -Data $deleted
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

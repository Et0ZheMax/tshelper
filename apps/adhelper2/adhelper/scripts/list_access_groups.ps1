. "$PSScriptRoot/common.ps1"
try {
    Import-Module ActiveDirectory
    $inputData = Read-InputJson
    $domain = $inputData.domain
    $searchBase = [string]$domain.group_search_base
    if ([string]::IsNullOrWhiteSpace($searchBase)) {
        throw "OU групп доступа не настроен"
    }
    $server = Get-DomainServer $domain
    $null = Get-ADObject -Server $server -Identity $searchBase -ErrorAction Stop
    $groups = @(Get-ADGroup -Server $server -Filter * -SearchBase $searchBase -SearchScope Subtree `
        -Properties Description,Info,ManagedBy,GroupScope,GroupCategory -ErrorAction Stop)
    $rows = @()
    foreach ($group in $groups) {
        $rows += [pscustomobject]@{
            domain = [string]$domain.name
            name = [string]$group.Name
            sam = [string]$group.SamAccountName
            description = [string]$group.Description
            info = [string]$group.Info
            dn = [string]$group.DistinguishedName
            managedBy = [string]$group.ManagedBy
            scope = [string]$group.GroupScope
            category = [string]$group.GroupCategory
        }
    }
    Write-JsonResult -Ok $true -Data @($rows | Sort-Object -Property sam)
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

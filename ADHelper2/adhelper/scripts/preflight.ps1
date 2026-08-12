. "$PSScriptRoot/common.ps1"
try {
    $inputData = Read-InputJson
    $moduleAvailable = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
    $domainStates = @()
    if ($moduleAvailable) { Import-Module ActiveDirectory }
    foreach ($domain in @($inputData.domains)) {
        $serverOk = $false; $ouOk = $false; $server = [string]$domain.server; $message = ''
        if ($moduleAvailable) {
            try {
                $server = Get-DomainServer $domain
                Get-ADDomain -Server $server | Out-Null
                $serverOk = $true
                Get-ADOrganizationalUnit -Server $server -Identity ([string]$domain.ou_dn) | Out-Null
                $ouOk = $true
            } catch { $message = $_.Exception.Message }
        } else { $message = 'Модуль ActiveDirectory не установлен' }
        $domainStates += [pscustomobject]@{ name=[string]$domain.name; server=$server; server_ok=$serverOk; ou_ok=$ouOk; message=$message }
    }
    Write-JsonResult -Ok $true -Data ([pscustomobject]@{
        powershell_version = $PSVersionTable.PSVersion.ToString()
        ad_module = $moduleAvailable
        domains = $domainStates
    })
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

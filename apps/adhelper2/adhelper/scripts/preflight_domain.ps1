. "$PSScriptRoot/common.ps1"
$inputData = [pscustomobject]@{ domain = [pscustomobject]@{} }
try {
    $inputData = Read-InputJson
    $domain = $inputData.domain
    Import-Module ActiveDirectory -ErrorAction Stop

    $configuredServer = [string]$domain.server
    $server = $configuredServer
    $serverOk = $false
    $ouOk = $false
    $message = ''

    if ([string]::IsNullOrWhiteSpace($configuredServer)) {
        throw 'В настройках домена не указан контроллер'
    }

    # Командлеты ActiveDirectory используют AD Web Services (TCP 9389).
    # Короткая проверка не даёт диагностике бесконечно ждать недоступный узел.
    if (-not (Test-TcpEndpoint -HostName $configuredServer -Port 9389 -TimeoutMs 3000)) {
        throw "Контроллер $configuredServer недоступен по TCP 9389 (AD Web Services)"
    }

    $rootDse = Get-ADRootDSE -Server $configuredServer -ErrorAction Stop
    $serverOk = $true
    if ($rootDse.dnsHostName) { $server = [string]$rootDse.dnsHostName }

    $ouDn = [string]$domain.ou_dn
    if ([string]::IsNullOrWhiteSpace($ouDn)) {
        throw 'В настройках домена не указан базовый OU'
    }
    Get-ADOrganizationalUnit -Server $server -Identity $ouDn -ErrorAction Stop | Out-Null
    $ouOk = $true

    Write-JsonResult -Ok $true -Data ([pscustomobject]@{
        name = [string]$domain.name
        label = [string]$domain.label
        server = $server
        configured_server = $configuredServer
        server_ok = $serverOk
        ou_ok = $ouOk
        message = $message
    })
} catch {
    $domain = $inputData.domain
    Write-JsonResult -Ok $true -Data ([pscustomobject]@{
        name = [string]$domain.name
        label = [string]$domain.label
        server = [string]$domain.server
        configured_server = [string]$domain.server
        server_ok = $false
        ou_ok = $false
        message = $_.Exception.Message
    })
}

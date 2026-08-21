. "$PSScriptRoot/common.ps1"
try {
    $inputData = Read-InputJson
    $available = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
    $imported = $false
    $message = ''
    if ($available) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $imported = $true
        } catch {
            $message = $_.Exception.Message
        }
    } else {
        $message = 'Модуль ActiveDirectory не установлен'
    }
    Write-JsonResult -Ok $true -Data ([pscustomobject]@{
        powershell_version = $PSVersionTable.PSVersion.ToString()
        module_available = $available
        ad_module = $imported
        message = $message
    })
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

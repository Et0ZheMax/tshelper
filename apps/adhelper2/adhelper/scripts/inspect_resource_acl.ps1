. "$PSScriptRoot/common.ps1"
try {
    $inputData = Read-InputJson
    $path = [string]$inputData.path
    if ([string]::IsNullOrWhiteSpace($path)) {
        Write-JsonResult -Ok $true -Data ([pscustomobject]@{ available = $false; path = ''; entries = @(); message = 'Путь не указан' })
        exit 0
    }
    if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
        Write-JsonResult -Ok $true -Data ([pscustomobject]@{ available = $false; path = $path; entries = @(); message = 'Ресурс недоступен с этого компьютера' })
        exit 0
    }
    try {
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
    } catch {
        Write-JsonResult -Ok $true -Data ([pscustomobject]@{ available = $false; path = $path; entries = @(); message = $_.Exception.Message })
        exit 0
    }
    $entries = @()
    foreach ($entry in @($acl.Access)) {
        $identity = [string]$entry.IdentityReference
        $sam = $identity
        if ($identity.Contains('\')) { $sam = $identity.Substring($identity.LastIndexOf('\') + 1) }
        $entries += [pscustomobject]@{
            identity = $identity
            sam = $sam
            rights = [string]$entry.FileSystemRights
            accessType = [string]$entry.AccessControlType
            inherited = [bool]$entry.IsInherited
        }
    }
    Write-JsonResult -Ok $true -Data ([pscustomobject]@{
        available = $true
        path = $path
        owner = [string]$acl.Owner
        entries = @($entries)
        message = ''
    })
} catch {
    Write-JsonResult -Ok $false -Message $_.Exception.Message
    exit 1
}

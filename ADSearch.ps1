$root = Split-Path -Parent $MyInvocation.MyCommand.Path

'ADSearch.Core.ps1',
'ADSearch.Filters.ps1',
'ADSearch.Objects.ps1',
'ADSearch.Directory.ps1',
'ADSearch.Gpo.ps1',
'ADSearch.Dns.ps1',
'ADSearch.Exchange.ps1',
'ADSearch.ExchangeRecipients.ps1',
'ADSearch.Diagnostics.ps1',
'ADSearch.SelfTest.ps1' | ForEach-Object {
    . (Join-Path $root $_)
}

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host 'ADSearch は . .\ADSearch.ps1 で読み込んでください'
}

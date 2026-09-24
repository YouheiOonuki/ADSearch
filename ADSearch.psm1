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

# 公開関数は ADSearch.psd1 の FunctionsToExport を唯一の真実源とする（登録漏れ防止）。
$manifest = Import-PowerShellDataFile (Join-Path $root 'ADSearch.psd1')
Export-ModuleMember -Function $manifest.FunctionsToExport

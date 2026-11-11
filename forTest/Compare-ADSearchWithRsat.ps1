# ============================================================
# Compare-ADSearchWithRsat.ps1
# ADSearch の結果を、RSAT の本物（ActiveDirectory・DnsServer・GroupPolicy モジュール）の結果と並べて突き合わせる。
#
# どこで流すか:
#   - DC の上（RSAT のモジュールがそろっている）。**Domain Users の一般ユーザーで**流すこと
#     （管理者で流すと、一般ユーザーでは読めない属性まで読めてしまい、権限の問題が隠れる）
#       runas /user:CORP\adsearch-ol powershell
#   - RSAT を入れたドメイン参加の Windows 11 でも流せる（クライアントからの経路も確かめられる）
#   ※ DnsServer モジュールは DC 以外では -ComputerName で DNS サーバーへ RPC する。一般ユーザーでは
#     拒否されることがあり、その項目は Skip になる
#
# 使い方:
#   powershell -ExecutionPolicy Bypass -File .\forTest\Compare-ADSearchWithRsat.ps1 -Server dc01.corp.local
# 全件 OK なら終了コード 0、1 件でも NG なら 1。Skip は失敗にしない（表に残る）
# 読むだけ。AD にも DNS にも書き込まない
# ============================================================
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [string]$GpoTarget   # GPO のリンクを比べる OU の DN（省略時は比べない）
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Get-Module ADSearch | Remove-Module
Import-Module (Join-Path $root 'ADSearch.psd1') -Force | Out-Null

$rows = New-Object System.Collections.Generic.List[object]
function Row([string]$Name, [string]$Result, [string]$Detail) { $rows.Add([pscustomobject]@{ Check = $Name; Result = $Result; Detail = $Detail }) }
function Same([string]$Name, $Rsat, $Ads) {
    $a = (@($Rsat) | Sort-Object) -join ' | '; $b = (@($Ads) | Sort-Object) -join ' | '
    if ($a -ceq $b) { Row $Name 'OK' "$(@($Rsat).Count) 件一致" }
    else {
        $onlyR = @(@($Rsat) | Where-Object { @($Ads) -notcontains $_ }); $onlyA = @(@($Ads) | Where-Object { @($Rsat) -notcontains $_ })
        Row $Name 'NG' ("RSAT だけ: " + (($onlyR | Select-Object -First 5) -join ', ') + " / ADSearch だけ: " + (($onlyA | Select-Object -First 5) -join ', '))
    }
}
function Need([string]$Module) {
    if (Get-Module -ListAvailable $Module) { Import-Module $Module -ErrorAction Stop; return $true }
    Row "($Module)" 'Skip' "$Module モジュールが無い"; return $false
}

# --- ドメイン・フォレスト・DC -----------------------------------------
if (Need 'ActiveDirectory') {
    $rd = ActiveDirectory\Get-ADDomain -Server $Server; $ad = ADSearch\Get-ADDomain -Server $Server
    Same 'Get-ADDomain: DNSRoot・NetBIOSName・DomainMode' @("$($rd.DNSRoot)/$($rd.NetBIOSName)/$($rd.DomainMode)") @("$($ad.DNSRoot)/$($ad.NetBIOSName)/$($ad.DomainMode)")
    $rf = ActiveDirectory\Get-ADForest -Server $Server; $af = ADSearch\Get-ADForest -Server $Server
    Same 'Get-ADForest: ForestMode' @("$($rf.ForestMode)") @("$($af.ForestMode)")
    Same 'Get-ADForest: Domains'    @($rf.Domains) @($af.Domains)
    Same 'Get-ADDomainController -Filter *: 名前とドメイン' `
        @(ActiveDirectory\Get-ADDomainController -Filter * -Server $Server | ForEach-Object { "$($_.Name)@$($_.Domain)@$($_.Site)" }) `
        @(ADSearch\Get-ADDomainController -Server $Server | ForEach-Object { "$($_.Name)@$($_.Domain)@$($_.Site)" })
    Same 'Get-ADReplicationSubnet: 名前' @(ActiveDirectory\Get-ADReplicationSubnet -Filter * -Server $Server | ForEach-Object Name) @(ADSearch\Get-ADReplicationSubnet -Server $Server | ForEach-Object Name)
}

# --- GPO のリンクの順序 ------------------------------------------------
if ($GpoTarget -and (Need 'GroupPolicy')) {
    $ri = Get-GPInheritance -Target $GpoTarget -Domain (ADSearch\Get-ADDomain -Server $Server).DNSRoot -Server $Server
    Same 'Get-ADGpoLink: 順序・名前・強制' `
        @($ri.GpoLinks | ForEach-Object { "$($_.Order):$($_.DisplayName):$($_.Enforced)" }) `
        @(ADSearch\Get-ADGpoLink -Target $GpoTarget -Server $Server | ForEach-Object { "$($_.Order):$($_.GpoName):$($_.Enforced)" })
}

# --- DNS --------------------------------------------------------------
if (Need 'DnsServer') {
    try { $rz = @(DnsServer\Get-DnsServerZone -ComputerName $Server | Where-Object { $_.IsDsIntegrated }) }
    catch { $rz = $null; Row 'DnsServer\Get-DnsServerZone' 'Skip' "RSAT 側が読めない（権限の可能性）: $($_.Exception.Message)" }
    if ($null -ne $rz) {
        $az = @(ADSearch\Get-DnsServerZone -ComputerName $Server)
        Same 'Get-DnsServerZone: AD 統合ゾーンの名前・種類・動的更新・置き場' `
            @($rz | Where-Object { $_.ZoneName -ne 'RootDNSServers' } | ForEach-Object { "$($_.ZoneName)/$($_.ZoneType)/$($_.DynamicUpdate)/$($_.ReplicationScope)" }) `
            @($az | ForEach-Object { "$($_.ZoneName)/$($_.ZoneType)/$($_.DynamicUpdate)/$($_.ReplicationScope)" })
        foreach ($z in ($rz | Where-Object { $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' })) {
            # レコードの中身を 1 行にする（RSAT と ADSearch で同じ書き方）
            $fmt = {
                param($r)
                $d = $r.RecordData
                $v = switch ($r.RecordType) {
                    'A' { $d.IPv4Address } 'AAAA' { $d.IPv6Address } 'CNAME' { $d.HostNameAlias } 'NS' { $d.NameServer } 'PTR' { $d.PtrDomainName }
                    'MX' { "$($d.Preference) $($d.MailExchange)" } 'SRV' { "$($d.Priority) $($d.Weight) $($d.Port) $($d.DomainName)" }
                    'SOA' { "$($d.SerialNumber) $($d.PrimaryServer) $($d.ResponsiblePerson)" } 'TXT' { $d.DescriptiveText } default { '?' }
                }
                "$($r.HostName) $($r.RecordType) $([int]$r.TimeToLive.TotalSeconds) $v"
            }
            $rr = @(DnsServer\Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ComputerName $Server | ForEach-Object { & $fmt $_ })
            $ar = @(ADSearch\Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ComputerName $Server | ForEach-Object { & $fmt $_ })
            Same "Get-DnsServerResourceRecord: $($z.ZoneName)" $rr $ar
        }
    }
}

"`n==== ADSearch と RSAT の突き合わせ ===="
$rows | Format-Table Check, Result, Detail -AutoSize -Wrap
$ng = @($rows | Where-Object Result -eq 'NG').Count
"`n項目: $($rows.Count)  OK: $(@($rows | Where-Object Result -eq 'OK').Count)  NG: $ng  Skip: $(@($rows | Where-Object Result -eq 'Skip').Count)"
Get-Module ADSearch | Remove-Module
if ($ng -gt 0) { exit 1 }
exit 0

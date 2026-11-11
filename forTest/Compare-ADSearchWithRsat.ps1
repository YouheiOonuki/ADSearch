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
    [string]$GpoTarget,     # GPO のリンクを比べる OU の DN（省略時は比べない）
    [string]$SampleUser,    # 比べるユーザーの sAMAccountName（省略時は比べない。機微なアカウントは指定しない）
    [string]$SampleGroup,   # 比べるグループ（メンバーも比べる。Domain Admins などは指定しない: MDI の偵察検知に当たる）
    [string]$SampleComputer # 比べるコンピューター
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
# 1 つの比べ方が例外になっても全体を止めない: その文を NG として表に残し、次の文へ進む
function OnError($e) {
    $at = $e.InvocationInfo
    Row "(例外) 行 $($at.ScriptLineNumber)" 'NG' ("$($e.Exception.Message) | " + $at.Line.Trim().Substring(0, [Math]::Min(120, $at.Line.Trim().Length)))
}
# 各ブロックの先頭に置く trap（ブロックの中に置くと、例外の文の次から続く）
trap { OnError $_; continue }
function Need([string]$Module) {
    if (Get-Module -ListAvailable $Module) { Import-Module $Module -ErrorAction Stop; return $true }
    Row "($Module)" 'Skip' "$Module モジュールが無い"; return $false
}

# --- ドメイン・フォレスト・DC -----------------------------------------
if (Need 'ActiveDirectory') {
    trap { OnError $_; continue }
    $rd = ActiveDirectory\Get-ADDomain -Server $Server; $ad = ADSearch\Get-ADDomain -Server $Server
    Same 'Get-ADDomain: DNSRoot・NetBIOSName・DomainMode' @("$($rd.DNSRoot)/$($rd.NetBIOSName)/$($rd.DomainMode)") @("$($ad.DNSRoot)/$($ad.NetBIOSName)/$($ad.DomainMode)")
    $rf = ActiveDirectory\Get-ADForest -Server $Server; $af = ADSearch\Get-ADForest -Server $Server
    Same 'Get-ADForest: ForestMode' @("$($rf.ForestMode)") @("$($af.ForestMode)")
    Same 'Get-ADForest: Domains'    @($rf.Domains) @($af.Domains)
    Same 'Get-ADDomain: FSMO（PDC・RID・Infrastructure）' @("$($rd.PDCEmulator)/$($rd.RIDMaster)/$($rd.InfrastructureMaster)") @("$($ad.PDCEmulator)/$($ad.RIDMaster)/$($ad.InfrastructureMaster)")
    Same 'Get-ADDomain: DomainSID' @("$($rd.DomainSID)") @("$($ad.DomainSID)")
    Same 'Get-ADForest: FSMO（Schema・DomainNaming）' @("$($rf.SchemaMaster)/$($rf.DomainNamingMaster)") @("$($af.SchemaMaster)/$($af.DomainNamingMaster)")
    Same 'Get-ADForest: GlobalCatalogs'        @($rf.GlobalCatalogs) @($af.GlobalCatalogs)
    Same 'Get-ADForest: ApplicationPartitions' @($rf.ApplicationPartitions) @($af.ApplicationPartitions)
    Same 'Get-ADForest: UPNSuffixes'           @($rf.UPNSuffixes) @($af.UPNSuffixes)
    Same 'Get-ADForest: Sites'                 @($rf.Sites) @($af.Sites)
    $dcLine = { param($d) "$($d.Name)@$($d.Domain)@$($d.Site)/$($d.HostName)/GC=$($d.IsGlobalCatalog)/RO=$($d.IsReadOnly)/$($d.IPv4Address)/$($d.OperatingSystem)/$($d.ComputerObjectDN)" }
    Same 'Get-ADDomainController -Filter *' `
        @(ActiveDirectory\Get-ADDomainController -Filter * -Server $Server | ForEach-Object { & $dcLine $_ }) `
        @(ADSearch\Get-ADDomainController -Filter * -Server $Server | ForEach-Object { & $dcLine $_ })
    Same 'Get-ADDomainController -Filter "IsGlobalCatalog -eq $true"' `
        @(ActiveDirectory\Get-ADDomainController -Filter 'IsGlobalCatalog -eq $true' -Server $Server | ForEach-Object Name) `
        @(ADSearch\Get-ADDomainController -Filter 'IsGlobalCatalog -eq $true' -Server $Server | ForEach-Object Name)
    $rp = ActiveDirectory\Get-ADDefaultDomainPasswordPolicy -Server $Server; $ap = ADSearch\Get-ADDefaultDomainPasswordPolicy -Server $Server
    $ppLine = { param($p) "$($p.MinPasswordLength)/$($p.PasswordHistoryCount)/$($p.LockoutThreshold)/$($p.MaxPasswordAge)/$($p.MinPasswordAge)/$($p.LockoutDuration)/$($p.LockoutObservationWindow)/$($p.ComplexityEnabled)/$($p.ReversibleEncryptionEnabled)" }
    Same 'Get-ADDefaultDomainPasswordPolicy' @(& $ppLine $rp) @(& $ppLine $ap)
    Same 'Get-ADTrust' `
        @(ActiveDirectory\Get-ADTrust -Filter * -Server $Server | ForEach-Object { "$($_.Name)/$($_.Direction)/$($_.TrustType)/$($_.ForestTransitive)/$($_.IntraForest)" }) `
        @(ADSearch\Get-ADTrust -Server $Server | ForEach-Object { "$($_.Name)/$($_.Direction)/$($_.TrustType)/$($_.ForestTransitive)/$($_.IntraForest)" })
    Same 'Get-ADReplicationSite' @(ActiveDirectory\Get-ADReplicationSite -Filter * -Server $Server | ForEach-Object Name) @(ADSearch\Get-ADReplicationSite -Server $Server | ForEach-Object Name)
    Same 'Get-ADReplicationSiteLink: 名前・Cost・間隔・サイト' `
        @(ActiveDirectory\Get-ADReplicationSiteLink -Filter * -Server $Server | ForEach-Object { "$($_.Name)/$($_.Cost)/$($_.ReplicationFrequencyInMinutes)/$((@($_.SitesIncluded) | Sort-Object) -join ';')" }) `
        @(ADSearch\Get-ADReplicationSiteLink -Server $Server | ForEach-Object { "$($_.Name)/$($_.Cost)/$($_.ReplicationFrequencyInMinutes)/$((@($_.SitesIncluded) | Sort-Object) -join ';')" })
    Same 'Get-ADReplicationSubnet: 名前・Site・Location' `
        @(ActiveDirectory\Get-ADReplicationSubnet -Filter * -Server $Server | ForEach-Object { "$($_.Name)/$($_.Site)/$($_.Location)" }) `
        @(ADSearch\Get-ADReplicationSubnet -Server $Server | ForEach-Object { "$($_.Name)/$($_.Site)/$($_.Location)" })
    Same 'Get-ADReplicationConnection: 送る側→受け取る側・KCC' `
        @(ActiveDirectory\Get-ADReplicationConnection -Filter * -Server $Server | ForEach-Object { "$($_.ReplicateFromDirectoryServer)>$($_.ReplicateToDirectoryServer)/$($_.AutoGenerated)" }) `
        @(ADSearch\Get-ADReplicationConnection -Server $Server | ForEach-Object { "$($_.ReplicateFromDirectoryServer)>$($_.ReplicateToDirectoryServer)/$($_.AutoGenerated)" })

    # 既定の欄の値（RSAT の既定の出力と同じ名前の欄だけを比べる）
    $cmpObj = {
        param([string]$Label, $R, $A, [string[]]$Props)
        foreach ($n in $Props) { Same "$Label`: $n" @("$($R.$n)") @("$($A.$n)") }
    }
    if ($SampleUser) {
        trap { OnError $_; continue }
        $props = 'DistinguishedName','Name','SamAccountName','UserPrincipalName','Enabled','SID','ObjectGUID','GivenName','Surname'
        & $cmpObj "Get-ADUser $SampleUser" (ActiveDirectory\Get-ADUser $SampleUser -Server $Server) (ADSearch\Get-ADUser $SampleUser -Server $Server -Properties GivenName, Surname) $props
        $more = 'LockedOut','PasswordExpired','PasswordNeverExpires','PasswordLastSet','LastLogonDate','AccountExpirationDate','MemberOf'
        $r = ActiveDirectory\Get-ADUser $SampleUser -Server $Server -Properties $more; $a = ADSearch\Get-ADUser $SampleUser -Server $Server -Properties $more
        foreach ($n in $more) {
            if ($n -eq 'MemberOf') { Same "Get-ADUser $SampleUser`: MemberOf" @($r.MemberOf) @($a.MemberOf) }
            else { Same "Get-ADUser $SampleUser`: $n" @("$($r.$n)") @("$($a.$n)") }
        }
    }
    if ($SampleGroup) {
        trap { OnError $_; continue }
        & $cmpObj "Get-ADGroup $SampleGroup" (ActiveDirectory\Get-ADGroup $SampleGroup -Server $Server) (ADSearch\Get-ADGroup $SampleGroup -Server $Server) @('DistinguishedName','SamAccountName','GroupScope','GroupCategory','SID','ObjectGUID')
        Same "Get-ADGroupMember $SampleGroup" @(ActiveDirectory\Get-ADGroupMember $SampleGroup -Server $Server | ForEach-Object DistinguishedName) @(ADSearch\Get-ADGroupMember $SampleGroup -Server $Server | ForEach-Object DistinguishedName)
        Same "Get-ADGroupMember $SampleGroup -Recursive" @(ActiveDirectory\Get-ADGroupMember $SampleGroup -Recursive -Server $Server | ForEach-Object DistinguishedName) @(ADSearch\Get-ADGroupMember $SampleGroup -Recursive -Server $Server | ForEach-Object DistinguishedName)
    }
    if ($SampleComputer) {
        trap { OnError $_; continue }
        & $cmpObj "Get-ADComputer $SampleComputer" (ActiveDirectory\Get-ADComputer $SampleComputer -Server $Server -Properties OperatingSystem) (ADSearch\Get-ADComputer $SampleComputer -Server $Server) @('DistinguishedName','DNSHostName','Enabled','SamAccountName','SID','OperatingSystem')
    }
}

# --- GPO のリンクの順序 ------------------------------------------------
if ($GpoTarget -and (Need 'GroupPolicy')) {
    trap { OnError $_; continue }
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
        trap { OnError $_; continue }
        $az = @(ADSearch\Get-DnsServerZone -ComputerName $Server)
        Same 'Get-DnsServerZone: AD 統合ゾーンの名前・種類・動的更新・置き場' `
            @($rz | Where-Object { $_.ZoneName -ne 'RootDNSServers' } | ForEach-Object { "$($_.ZoneName)/$($_.ZoneType)/$($_.DynamicUpdate)/$($_.ReplicationScope)" }) `
            @($az | ForEach-Object { "$($_.ZoneName)/$($_.ZoneType)/$($_.DynamicUpdate)/$($_.ReplicationScope)" })
        foreach ($z in ($rz | Where-Object { $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' })) {
            trap { OnError $_; continue }
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

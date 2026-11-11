# ============================================================
# ADSearch オフラインテスト（AD 不要）
# 目的: -Filter / -Identity から作る LDAP フィルターが正しいかを、ドメインに接続せずに確かめる
#       AD への問い合わせ（ADSI_Query など）はテスト用の偽物に差し替え、渡されたフィルターだけを記録する
# 使い方: PowerShell 5.1 / 7 のどちらでも
#   powershell -ExecutionPolicy Bypass -File .\forTest\Test-ADSearchOffline.ps1
# 全件 OK なら終了コード 0、1 件でも NG なら 1
# ============================================================

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Get-Module ADSearch | Remove-Module
$mod = Import-Module (Join-Path $root 'ADSearch.psd1') -Force -PassThru

$script:fail = 0
$script:count = 0
function Check([string]$Name, $Actual, $Expected) {
    $script:count++
    if ([string]$Actual -ceq [string]$Expected) {
        Write-Host "OK  $Name"
    }
    else {
        $script:fail++
        Write-Host "NG  $Name" -ForegroundColor Red
        Write-Host "      期待: $Expected"
        Write-Host "      実際: $Actual"
    }
}
function CheckThrows([string]$Name, [scriptblock]$Block) {
    $script:count++
    try { & $Block | Out-Null; $script:fail++; Write-Host "NG  $Name（例外になるはずが、ならなかった）" -ForegroundColor Red }
    catch { Write-Host "OK  $Name" }
}
# モジュール内部の関数を呼ぶ
function InModule([scriptblock]$Block, [object[]]$ArgList) { & $mod $Block @ArgList }

# ------------------------------------------------------------
Write-Host '--- -Filter の真偽値（引用符の有無）'
$disabledBit = '(userAccountControl:1.2.840.113556.1.4.803:=2)'
$pneBit      = '(userAccountControl:1.2.840.113556.1.4.803:=65536)'
$toLdap = { param($f) ADSI_PsFilterToLdap $f }
Check 'Enabled -eq $true（引用符なし）'           (InModule $toLdap @('Enabled -eq $true'))       "(!$disabledBit)"
Check "Enabled -eq '`$true'（引用符付き）"        (InModule $toLdap @('Enabled -eq ''$true'''))   "(!$disabledBit)"
Check 'Enabled -eq "$false"（二重引用符付き）'    (InModule $toLdap @('Enabled -eq "$false"'))    $disabledBit
Check "Enabled -eq 'True'（`"...`" で展開済み）"  (InModule $toLdap @("Enabled -eq '$true'"))     "(!$disabledBit)"
Check "PasswordNeverExpires -eq '`$true'"         (InModule $toLdap @('PasswordNeverExpires -eq ''$true''')) $pneBit
Check 'PasswordNeverExpires -ne $true'            (InModule $toLdap @('PasswordNeverExpires -ne $true'))     "(!$pneBit)"
Check '括弧と -or の混在' (InModule $toLdap @('(Title -like ''*Manager*'' -or Title -like ''*Director*'') -and Enabled -eq ''$true''')) "(&(|(title=*Manager*)(title=*Director*))(!$disabledBit))"

# ------------------------------------------------------------
Write-Host '--- -Filter の日時'
$gt = { param($s) (ADSI_ParseFilterDate $s).ToString('yyyy-MM-dd HH:mm:ss') }
Check '2026-01-05'          (InModule $gt @('2026-01-05'))          '2026-01-05 00:00:00'
Check '2026/1/5（1 桁）'    (InModule $gt @('2026/1/5'))            '2026-01-05 00:00:00'
Check '2026-1-5 9:05'       (InModule $gt @('2026-1-5 9:05'))       '2026-01-05 09:05:00'
Check '2026/01/05 09:05:30' (InModule $gt @('2026/01/05 09:05:30')) '2026-01-05 09:05:30'
Check '2026-01-05T23:59:59' (InModule $gt @('2026-01-05T23:59:59')) '2026-01-05 23:59:59'
CheckThrows '01/05/2026（月日年は受け付けない）' { InModule $gt @('01/05/2026') }
CheckThrows 'Jan 5 2026（英語表記は受け付けない）' { InModule $gt @('Jan 5 2026') }
$ft = [datetime]::new(2026, 1, 5, 0, 0, 0, [DateTimeKind]::Local).ToFileTime()
Check "LastLogonDate -lt '2026/1/5'" (InModule $toLdap @('LastLogonDate -lt ''2026/1/5''')) "(!(lastLogonTimestamp>=$ft))"
Check 'LastLogonDate -ge 134000000000000000（FileTime の数値）' (InModule $toLdap @('LastLogonDate -ge 134000000000000000')) '(lastLogonTimestamp>=134000000000000000)'

# ------------------------------------------------------------
Write-Host '--- -Identity の種類'
$idf = { param($i, $k) ADSI_ResolveIdentityFilter $i -Kind $k }
Check 'Account: yamada'           (InModule $idf @('yamada', 'Account'))     '(sAMAccountName=yamada)'
Check 'Computer: pc001（$ なし）' (InModule $idf @('pc001', 'Computer'))     '(|(sAMAccountName=pc001)(sAMAccountName=pc001$))'
Check 'Computer: pc001$'          (InModule $idf @('pc001$', 'Computer'))    '(sAMAccountName=pc001$)'
Check 'Name: All Users'           (InModule $idf @('All Users', 'Name'))     '(name=All Users)'
Check 'Name: 括弧は LDAP 用に変換' (InModule $idf @('Site(1)', 'Name'))      '(name=Site\281\29)'
Check 'DN はどの種類でも DN'      (InModule $idf @('CN=Sub,DC=example,DC=local', 'Name')) '(distinguishedName=CN=Sub,DC=example,DC=local)'
Check 'GUID'                      (InModule $idf @('00000000-0000-0000-0000-000000000001', 'Name')) '(objectGUID=\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01)'

# ------------------------------------------------------------
Write-Host '--- コマンドが AD に送るフィルター（AD への問い合わせは偽物に差し替え）'
& $mod {
    $script:LastFilter = $null
    function script:ADSI_Query { param([string]$Filter) $script:LastFilter = $Filter; [pscustomobject]@{ Name = 'x'; DistinguishedName = 'CN=x' } }
    function script:ADSI_ExchangeRun { param([string]$Filter) $script:LastFilter = $Filter }
    function script:ADSI_GetNamingContexts { [pscustomobject]@{ Default = 'DC=example,DC=local'; Config = 'CN=Configuration,DC=example,DC=local' } }
    function script:ADSI_AddressListsBase { 'CN=All Address Lists,CN=Address Lists Container' }
    function script:ADSI_GalBase { 'CN=All Global Address Lists,CN=Address Lists Container' }
}
function Sent([scriptblock]$Call) {
    & $mod { $script:LastFilter = $null }
    & $Call | Out-Null
    & $mod { $script:LastFilter }
}
Check 'Get-ADUser yamada'                 (Sent { Get-ADUser yamada })                 '(&(&(objectCategory=person)(objectClass=user))(sAMAccountName=yamada))'
Check 'Get-ADComputer pc001'              (Sent { Get-ADComputer pc001 })              '(&(objectCategory=computer)(|(sAMAccountName=pc001)(sAMAccountName=pc001$)))'
Check 'Get-ADTrust -Identity child.example.local' (Sent { Get-ADTrust -Identity child.example.local }) '(&(objectClass=trustedDomain)(name=child.example.local))'
Check 'Get-ADReplicationSite -Identity Default-First-Site-Name' (Sent { Get-ADReplicationSite -Identity Default-First-Site-Name }) '(&(objectClass=site)(name=Default-First-Site-Name))'
Check 'Get-ADReplicationSubnet -Identity 10.0.0.0/8' (Sent { Get-ADReplicationSubnet -Identity 10.0.0.0/8 }) '(&(objectClass=subnet)(name=10.0.0.0/8))'
Check 'Get-AddressList -Identity "All Users"' (Sent { Get-AddressList -Identity 'All Users' }) '(&(objectClass=addressBookContainer)(name=All Users))'
Check 'Get-AcceptedDomain -Identity example.com' (Sent { Get-AcceptedDomain -Identity example.com }) '(&(objectClass=msExchAcceptedDomain)(name=example.com))'
Check "Get-ADUser -Filter `"PasswordNeverExpires -eq '```$true'`"" (Sent { Get-ADUser -Filter "PasswordNeverExpires -eq '`$true'" }) "(&(&(objectCategory=person)(objectClass=user))$pneBit)"

# ------------------------------------------------------------
# DNS（AD 統合ゾーン）。dnsRecord・dnsProperty のバイト列は MS-DNSP 2.3.2 の形で手で組む
# ------------------------------------------------------------
Write-Host '--- DNS: dnsRecord（DNS_RPC_RECORD）を解く'
function BE16([int]$v) { [byte[]]@((($v -shr 8) -band 0xff), ($v -band 0xff)) }
function BE32([uint32]$v) { [byte[]]@((($v -shr 24) -band 0xff), (($v -shr 16) -band 0xff), (($v -shr 8) -band 0xff), ($v -band 0xff)) }
function LE16([int]$v) { [byte[]][BitConverter]::GetBytes([uint16]$v) }
function LE32([uint32]$v) { [byte[]][BitConverter]::GetBytes([uint32]$v) }
# DNS_COUNT_NAME: 長さ（ラベルの並び + 終わりの 0）・ラベル数・ラベルの並び
function CountName([string]$n) {
    $labels = @($n.TrimEnd('.').Split('.') | Where-Object { $_ })
    $raw = New-Object System.Collections.Generic.List[byte]
    foreach ($l in $labels) { $b = [Text.Encoding]::UTF8.GetBytes($l); $raw.Add([byte]$b.Length); $raw.AddRange([byte[]]$b) }
    $raw.Add(0)
    [byte[]](@([byte]$raw.Count, [byte]$labels.Count) + $raw.ToArray())
}
function Rec([int]$Type, [uint32]$Ttl, [uint32]$Hours, [byte[]]$Data) {
    if ($null -eq $Data) { $Data = [byte[]]@() }
    [byte[]]((LE16 $Data.Length) + (LE16 $Type) + [byte[]]@(5, 0xF0) + (LE16 0) + (LE32 1) + (BE32 $Ttl) + (LE32 0) + (LE32 $Hours) + $Data)
}
function Prop([int]$Id, [byte[]]$Data) { [byte[]]((LE32 $Data.Length) + (LE32 1) + (LE32 0) + (LE32 1) + (LE32 $Id) + $Data + [byte[]]@(0)) }
$parse = { param($b) ADSI_ParseDnsRecord $b }

$r = InModule $parse @(, (Rec 1 3600 0 ([byte[]]@(192, 168, 10, 5))))
Check 'A: 型'                     $r.RecordType 'A'
Check 'A: アドレス'               $r.RecordData.IPv4Address '192.168.10.5'
Check 'A: TTL はビッグエンディアン' $r.TimeToLive.TotalSeconds 3600
Check 'A: 静的（時刻 0）は Timestamp なし' ($null -eq $r.Timestamp) $true
$h = [uint32]((([datetime]::new(2026, 1, 5, 9, 0, 0, [DateTimeKind]::Utc)) - [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).TotalHours)
$r = InModule $parse @(, (Rec 1 1200 $h ([byte[]]@(10, 0, 0, 1))))
Check 'A: 動的は 1601 年からの時間' $r.Timestamp.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') '2026-01-05 09:00'
$v6 = [System.Net.IPAddress]::Parse('2001:db8::1').GetAddressBytes()
$r = InModule $parse @(, (Rec 28 3600 0 $v6))
Check 'AAAA'                      $r.RecordData.IPv6Address '2001:db8::1'
$r = InModule $parse @(, (Rec 5 3600 0 (CountName 'www.example.local')))
Check 'CNAME（末尾にドット）'      $r.RecordData.HostNameAlias 'www.example.local.'
$r = InModule $parse @(, (Rec 2 3600 0 (CountName 'dc01.example.local')))
Check 'NS'                        $r.RecordData.NameServer 'dc01.example.local.'
$r = InModule $parse @(, (Rec 12 3600 0 (CountName 'pc001.example.local')))
Check 'PTR'                       $r.RecordData.PtrDomainName 'pc001.example.local.'
$r = InModule $parse @(, (Rec 15 3600 0 ((BE16 10) + (CountName 'mail.example.local'))))
Check 'MX: 優先度と名前'           "$($r.RecordData.Preference) $($r.RecordData.MailExchange)" '10 mail.example.local.'
$r = InModule $parse @(, (Rec 33 600 0 ((BE16 0) + (BE16 100) + (BE16 389) + (CountName 'dc01.example.local'))))
Check 'SRV: 優先度・重み・ポート・名前' $r.Data '0 100 389 dc01.example.local.'
$soa = (BE32 2026011501) + (BE32 900) + (BE32 600) + (BE32 86400) + (BE32 3600) + (CountName 'dc01.example.local') + (CountName 'hostmaster.example.local')
$r = InModule $parse @(, (Rec 6 3600 0 $soa))
Check 'SOA: 通番'                 $r.RecordData.SerialNumber 2026011501
Check 'SOA: 主サーバーと管理者'    "$($r.RecordData.PrimaryServer) $($r.RecordData.ResponsiblePerson)" 'dc01.example.local. hostmaster.example.local.'
Check 'SOA: 間隔'                 "$($r.RecordData.RefreshInterval.TotalSeconds)/$($r.RecordData.RetryDelay.TotalSeconds)/$($r.RecordData.ExpireLimit.TotalSeconds)/$($r.RecordData.MinimumTimeToLive.TotalSeconds)" '900/600/86400/3600'
$t1 = [Text.Encoding]::UTF8.GetBytes('v=spf1 '); $t2 = [Text.Encoding]::UTF8.GetBytes('-all')
$r = InModule $parse @(, (Rec 16 3600 0 ([byte[]](@([byte]$t1.Length) + $t1 + @([byte]$t2.Length) + $t2))))
Check 'TXT: 文字の並びをつなぐ'    $r.RecordData.DescriptiveText 'v=spf1 -all'
$r = InModule $parse @(, (Rec 99 3600 0 ([byte[]]@(0xAB, 0xCD))))
Check '知らない型は Type<番号> と 16 進' "$($r.RecordType) $($r.Data)" 'Type99 ABCD'
$r = InModule $parse @(, (Rec 0 0 0 ([byte[]]@(1, 2, 3, 4, 5, 6, 7, 8))))
Check 'ZERO（消した印）'          $r.RecordType 'ZERO'
Check '短すぎるバイト列は $null'   ($null -eq (InModule $parse @(, ([byte[]]@(1, 2, 3))))) $true

Write-Host '--- DNS: dnsProperty（ゾーンの設定）'
$zs = { param($blobs) ADSI_DnsZoneSettings $blobs }
$z = InModule $zs @(, @((Prop 1 (LE32 1)), (Prop 2 (LE32 2)), (Prop 0x40 (LE32 1)), (Prop 0x10 (LE32 168)), (Prop 0x20 (LE32 168))))
Check 'Primary・Secure・エージング' "$($z.ZoneType) $($z.DynamicUpdate) $($z.Aging)" 'Primary Secure True'
Check 'NoRefresh/Refresh は時間'    "$($z.NoRefreshInterval.TotalDays)/$($z.RefreshInterval.TotalDays)" '7/7'
$z = InModule $zs @(, @((Prop 1 (LE32 3)), (Prop 0x81 ((LE32 2) + [byte[]]@(10, 0, 0, 1) + [byte[]]@(10, 0, 0, 2)))))
Check 'Stub と IP4_ARRAY の転送先'  "$($z.ZoneType) $($z.MasterServers -join ',')" 'Stub 10.0.0.1,10.0.0.2'
# DNS_ADDR_ARRAY: 頭 32 バイト（AddrCount は 4 バイト目）+ DNS_ADDR 64 バイト（先頭が sockaddr）
$sa4 = [byte[]]((LE16 2) + (BE16 53) + [byte[]]@(192, 0, 2, 53) + (New-Object byte[] 56))
$sa6 = [byte[]]((LE16 23) + (BE16 53) + (LE32 0) + [System.Net.IPAddress]::Parse('2001:db8::53').GetAddressBytes() + (New-Object byte[] 40))
$da = [byte[]]((LE32 2) + (LE32 2) + (New-Object byte[] 24) + $sa4 + $sa6)
$z = InModule $zs @(, @((Prop 1 (LE32 4)), (Prop 0x91 $da)))
Check 'Forwarder と DNS_ADDR_ARRAY（IPv4・IPv6）' "$($z.ZoneType) $($z.MasterServers -join ',')" 'Forwarder 192.0.2.53,2001:db8::53'
$z = InModule $zs @(, @())
Check '設定なしは Primary・None' "$($z.ZoneType) $($z.DynamicUpdate) $($z.Aging)" 'Primary None False'

Write-Host '--- DNS: 置き場の一覧（crossRef から）'
$refs = @(
    @{ NCName = 'DC=example,DC=local';                          DnsRoot = 'example.local';                         SystemFlags = 3 }
    @{ NCName = 'DC=child,DC=example,DC=local';                 DnsRoot = 'child.example.local';                   SystemFlags = 3 }
    @{ NCName = 'CN=Configuration,DC=example,DC=local';         DnsRoot = 'example.local';                         SystemFlags = 1 }
    @{ NCName = 'CN=Schema,CN=Configuration,DC=example,DC=local'; DnsRoot = 'example.local';                       SystemFlags = 1 }
    @{ NCName = 'DC=DomainDnsZones,DC=example,DC=local';        DnsRoot = 'DomainDnsZones.example.local';          SystemFlags = 5 }
    @{ NCName = 'DC=DomainDnsZones,DC=child,DC=example,DC=local'; DnsRoot = 'DomainDnsZones.child.example.local';  SystemFlags = 5 }
    @{ NCName = 'DC=ForestDnsZones,DC=example,DC=local';        DnsRoot = 'ForestDnsZones.example.local';          SystemFlags = 5 }
    @{ NCName = 'DC=CustomDns,DC=example,DC=local';             DnsRoot = 'CustomDns.example.local';               SystemFlags = 5 }
)
$plan = { param($r, $s, $p) @(ADSI_DnsContainerPlan -CrossRefs $r -DomainNC 'DC=child,DC=example,DC=local' -RootNC 'DC=example,DC=local' -Scope $s -Partition $p) | ForEach-Object { "$($_.Scope):$($_.Container)" } }
Check '子ドメインから Domain 範囲' ((InModule $plan @($refs, 'Domain', 'All')) -join ' | ') ('Domain:CN=MicrosoftDNS,DC=DomainDnsZones,DC=child,DC=example,DC=local | Forest:CN=MicrosoftDNS,DC=ForestDnsZones,DC=example,DC=local | Legacy:CN=MicrosoftDNS,CN=System,DC=child,DC=example,DC=local | Custom:CN=MicrosoftDNS,DC=CustomDns,DC=example,DC=local')
Check 'Forest 範囲は親ドメインの置き場も' ((InModule $plan @($refs, 'Forest', 'All')).Count) 6
Check '-Partition Both は Domain と Forest だけ' ((InModule $plan @($refs, 'Domain', 'Both')) -join ' | ') 'Domain:CN=MicrosoftDNS,DC=DomainDnsZones,DC=child,DC=example,DC=local | Forest:CN=MicrosoftDNS,DC=ForestDnsZones,DC=example,DC=local'
Check '-Partition Legacy' ((InModule $plan @($refs, 'Forest', 'Legacy')) -join ' | ') 'Legacy:CN=MicrosoftDNS,CN=System,DC=child,DC=example,DC=local | Legacy:CN=MicrosoftDNS,CN=System,DC=example,DC=local'
$srv = { param($r) $p = @(ADSI_DnsContainerPlan -CrossRefs $r -DomainNC 'DC=child,DC=example,DC=local' -RootNC 'DC=example,DC=local' -Scope Forest); ($p | ForEach-Object { "$(ADSI_DnsServerFor $_ 'dc01.child.example.local')" }) -join ',' }
Check '接続先: 自ドメインは指定の DC、ほかは dnsRoot' (InModule $srv @(, $refs)) 'dc01.child.example.local,dc01.child.example.local,dc01.child.example.local,CustomDns.example.local,DomainDnsZones.example.local,example.local'

Write-Host '--- DNS: DN とエスケープ'
$zfd = { param($dn) ADSI_DnsZoneFromDN $dn }
Check 'ゾーン名（通常）'          (InModule $zfd @('DC=app1,DC=example.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local')) 'example.local'
Check 'ゾーン名（Legacy）'        (InModule $zfd @('DC=@,DC=example.local,CN=MicrosoftDNS,CN=System,DC=example,DC=local')) 'example.local'
Check 'ノード名に , があっても'    (InModule $zfd @('DC=a\,b,DC=example.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local')) 'example.local'
Check 'RDN のエスケープ'          (InModule { param($v) ADSI_DnsEscapeRdn $v } @('a,b+c')) 'a\,b\+c'

Write-Host '--- DNS: コマンドの出力（AD への問い合わせは偽物に差し替え）'
& $mod {
    $script:DnsCalls = New-Object System.Collections.Generic.List[string]
    function script:ADSI_DnsContainers {
        @(@{ Container = 'CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local'; Scope = 'Domain'; PartitionName = 'DomainDnsZones.example.local'; DnsRoot = 'DomainDnsZones.example.local'; Own = $true })
    }
    function script:ADSI_DnsSearchIn {
        param($Plan, $Server, [switch]$UseSSL, $Credential, [string]$Base, [string]$Filter, [string]$SearchScope, [string[]]$Properties)
        $script:DnsCalls.Add("$SearchScope|$Base|$Filter")
        $L = { param($v) $x = New-Object System.Collections.Generic.List[object]; foreach ($i in $v) { $x.Add($i) }; , $x }
        if ($Filter -like '*dnsZone*') {
            , @(
                @{ name = (& $L @('example.local')); dnsproperty = (& $L @((Prop 1 (LE32 1)), (Prop 2 (LE32 2)))); distinguishedname = (& $L @('DC=example.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local')); whencreated = (& $L @()); whenchanged = (& $L @()) }
                @{ name = (& $L @('10.in-addr.arpa')); dnsproperty = (& $L @()); distinguishedname = (& $L @('DC=10.in-addr.arpa,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local')); whencreated = (& $L @()); whenchanged = (& $L @()) }
                @{ name = (& $L @('..TrustAnchors')); dnsproperty = (& $L @()); distinguishedname = (& $L @('DC=..TrustAnchors,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local')); whencreated = (& $L @()); whenchanged = (& $L @()) }
                @{ name = (& $L @('..Deleted-old.local')); dnsproperty = (& $L @()); distinguishedname = (& $L @('DC=..Deleted-old.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local')); whencreated = (& $L @()); whenchanged = (& $L @()) }
                @{ name = (& $L @('RootDNSServers')); dnsproperty = (& $L @()); distinguishedname = (& $L @('DC=RootDNSServers,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local')); whencreated = (& $L @()); whenchanged = (& $L @()) }
            )
        }
        else {
            # byte[] が 1 つだけのときは @(, …) で包む（@(…) だとバイトにばらける）
            , @(
                @{ name = (& $L @('pc001')); dnsrecord = (& $L @((Rec 1 1200 0 ([byte[]]@(10, 0, 0, 5))), (Rec 28 1200 0 ([System.Net.IPAddress]::Parse('2001:db8::5').GetAddressBytes())))); distinguishedname = (& $L @('DC=pc001,DC=example.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local')); whenchanged = (& $L @()) }
                @{ name = (& $L @('gone')); dnsrecord = (& $L @(, (Rec 0 0 0 ([byte[]]@(1, 2, 3, 4, 5, 6, 7, 8))))); distinguishedname = (& $L @('DC=gone,DC=example.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local')); whenchanged = (& $L @()) }
            )
        }
    }
}
# 偽物の中で使う Rec・Prop・LE32 をモジュールから見えるようにする
& $mod { param($r, $p, $l) Set-Item function:script:Rec $r; Set-Item function:script:Prop $p; Set-Item function:script:LE32 $l; Set-Item function:script:LE16 ${function:LE16}; Set-Item function:script:BE32 ${function:BE32} } ${function:Rec} ${function:Prop} ${function:LE32}
& $mod { Set-Item function:script:LE16 { param([int]$v) [byte[]][BitConverter]::GetBytes([uint16]$v) }; Set-Item function:script:BE32 { param([uint32]$v) [byte[]]@((($v -shr 24) -band 0xff), (($v -shr 16) -band 0xff), (($v -shr 8) -band 0xff), ($v -band 0xff)) } }
$zones = @(Get-DnsServerZone)
Check 'Get-DnsServerZone: 消した・作りかけ・ルートヒントは出さない' (($zones | ForEach-Object ZoneName) -join ',') 'example.local,10.in-addr.arpa,TrustAnchors'
Check 'Get-DnsServerZone: 欄' "$($zones[0].ZoneType) $($zones[0].DynamicUpdate) $($zones[0].ReplicationScope) $($zones[0].IsDsIntegrated) $($zones[0].DirectoryPartitionName)" 'Primary Secure Domain True DomainDnsZones.example.local'
Check 'Get-DnsServerZone: 逆引き'   "$($zones[0].IsReverseLookupZone) $($zones[1].IsReverseLookupZone)" 'False True'
& $mod { $script:DnsCalls.Clear() }
$rr = @(Get-DnsServerResourceRecord -ZoneName example.local)
Check 'Get-DnsServerResourceRecord: 消したレコードは出さない' (($rr | ForEach-Object { "$($_.HostName)/$($_.RecordType)" }) -join ',') 'pc001/A,pc001/AAAA'
Check 'Get-DnsServerResourceRecord: RSAT と同じ欄' (($rr[0].PSObject.Properties.Name) -join ',') 'HostName,RecordType,Type,Timestamp,TimeToLive,RecordData'
Check 'Get-DnsServerResourceRecord: 探す場所とフィルター' (& $mod { $script:DnsCalls[0] }) 'Subtree|DC=example.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local|(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))'
$rr = @(Get-DnsServerResourceRecord -ZoneName example.local -RRType AAAA)
Check 'Get-DnsServerResourceRecord -RRType' (($rr | ForEach-Object { $_.RecordData.IPv6Address }) -join ',') '2001:db8::5'
& $mod { $script:DnsCalls.Clear() }
$ad = @(Get-ADDnsRecord -Name pc001 -IncludeTombstoned)
Check 'Get-ADDnsRecord -Name のフィルター（消したものも）' (& $mod { $script:DnsCalls[0] }) 'Subtree|CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=local|(&(objectClass=dnsNode)(name=pc001))'
Check 'Get-ADDnsRecord: ゾーン・Data・範囲' "$($ad[0].ZoneName) $($ad[0].Data) $($ad[0].ReplicationScope)" 'example.local 10.0.0.5 Domain'
Check 'Get-ADDnsRecord -IncludeTombstoned で ZERO も' (($ad | ForEach-Object RecordType) -join ',') 'A,AAAA,ZERO'
# 無いゾーン: 置き場が見つからない（偽物は $null を返す）ときは RSAT と同じくエラー
& $mod {
    Set-Item function:script:ADSI_DnsSearchIn_Real ${function:script:ADSI_DnsSearchIn}
    Set-Item function:script:ADSI_DnsSearchIn {
        param($Plan, $Server, [switch]$UseSSL, $Credential, [string]$Base, [string]$Filter, [string]$SearchScope, [string[]]$Properties)
        if ($Base -like 'DC=nozone.local,*') { return $null }
        if ($Filter -like '*(name=nozone.local)*') { return , (New-Object System.Collections.Generic.List[object]) }
        ADSI_DnsSearchIn_Real @PSBoundParameters
    }
}
CheckThrows 'Get-DnsServerResourceRecord: 無いゾーンはエラー' { Get-DnsServerResourceRecord -ZoneName nozone.local }
CheckThrows 'Get-DnsServerZone -Name: 無いゾーンはエラー'      { Get-DnsServerZone -Name nozone.local }
Check 'Get-DnsServerZone: 名前なしで 0 件はエラーにしない' (@(Get-DnsServerZone).Count) 3

Write-Host '--- DNS: DNS_COUNT_NAME の長さの欄が終わりの 0 を含まない書き方でも、次の名前を正しく読む'
$cn1 = CountName 'dc01.example.local'; $cn1[0] = [byte]($cn1[0] - 1)
$soa2 = (BE32 7) + (BE32 900) + (BE32 600) + (BE32 86400) + (BE32 3600) + $cn1 + (CountName 'hostmaster.example.local')
$r = InModule $parse @(, (Rec 6 3600 0 $soa2))
Check 'SOA: 管理者（長さの欄が 1 少ない）' $r.RecordData.ResponsiblePerson 'hostmaster.example.local.'

Write-Host '--- レビューの直し（2026-11-11）'
Check '機能レベル 10 は Windows2025'    (InModule { ADSI_FunctionalLevelName 10 'Domain' }) 'Windows2025Domain'
Check '機能レベル 7 は Windows2016'     (InModule { ADSI_FunctionalLevelName 7 'Forest' }) 'Windows2016Forest'
Check 'ADSI_LeafCn: エスケープした , で切らない' (InModule { ADSI_LeafCn 'CN=Yamada\, Taro,OU=Users,DC=example,DC=local' }) 'Yamada, Taro'
Check 'ADSI_LeafCn: 通常'                (InModule { ADSI_LeafCn 'CN=Sales,OU=Groups,DC=example,DC=local' }) 'Sales'

# Get-ADGpoLink: gPLink の末尾がリンク順序 1
& $mod {
    function script:Get-ADOrganizationalUnit { [pscustomobject]@{ gPLink = '[LDAP://CN={BBBB0000-0000-0000-0000-000000000002},CN=Policies,CN=System,DC=example,DC=local;2][LDAP://CN={AAAA0000-0000-0000-0000-000000000001},CN=Policies,CN=System,DC=example,DC=local;0]' } }
    function script:ADSI_Query { @([pscustomobject]@{ Name = '{AAAA0000-0000-0000-0000-000000000001}'; DisplayName = 'GPO-A' }, [pscustomobject]@{ Name = '{BBBB0000-0000-0000-0000-000000000002}'; DisplayName = 'GPO-B' }) }
}
$links = @(Get-ADGpoLink -Target 'OU=Test,DC=example,DC=local')
Check 'Get-ADGpoLink: 末尾がリンク順序 1' (($links | ForEach-Object { "$($_.Order):$($_.GpoName):$($_.Enforced)" }) -join ',') '1:GPO-A:False,2:GPO-B:True'

# Get-AcceptedDomain: EMS の DomainType の名前
& $mod {
    function script:ADSI_ExchangeRun {
        @(0, 1, 2, 4) | ForEach-Object { [pscustomobject]@{ Name = "d$_"; msExchAcceptedDomainName = "d$_.example"; msExchAcceptedDomainFlags = $_; DistinguishedName = "CN=d$_" } }
    }
}
Check 'Get-AcceptedDomain: DomainType' ((@(Get-AcceptedDomain) | ForEach-Object DomainType) -join ',') 'Authoritative,ExternalRelay,InternalRelay,Authoritative'

# Get-ADDomainController: 接続先のドメインの DC だけ。Domain は serverReference から
& $mod {
    function script:ADSI_GetNamingContexts { [pscustomobject]@{ Default = 'DC=child,DC=example,DC=local'; Root = 'DC=example,DC=local'; Config = 'CN=Configuration,DC=example,DC=local'; DnsHostName = 'dc01.child.example.local' } }
    function script:New-ADSConnection { [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name Dispose -Value {} -PassThru }
    function script:ADSI_NewSearcher {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($s in @('DC01', 'ROOTDC')) {
            $rows.Add([pscustomobject]@{ Properties = @{ distinguishedname = @("CN=NTDS Settings,CN=$s,CN=Servers,CN=Tokyo,CN=Sites,CN=Configuration,DC=example,DC=local"); objectclass = @('top', 'nTDSDSA'); options = @(1) } })
        }
        $rows | Add-Member -MemberType ScriptMethod -Name Dispose -Value {} -Force
        [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name FindAll -Value { $rows }.GetNewClosure() -PassThru | Add-Member -MemberType ScriptMethod -Name Dispose -Value {} -PassThru
    }
    function script:ADSI_GetAttrs($Conn, $DN, $Attrs) {
        if ($DN -like 'CN=DC01,*') { @{ dnshostname = @('dc01.child.example.local'); serverreference = @('CN=DC01,OU=Domain Controllers,DC=child,DC=example,DC=local') } }
        else { @{ dnshostname = @('rootdc.example.local'); serverreference = @('CN=ROOTDC,OU=Domain Controllers,DC=example,DC=local') } }
    }
}
$dcs = @(Get-ADDomainController)
Check 'Get-ADDomainController: 接続先のドメインの DC だけ' (($dcs | ForEach-Object { "$($_.Name)@$($_.Domain)@$($_.Site)" }) -join ',') 'DC01@child.example.local@Tokyo'

# ------------------------------------------------------------
Write-Host ''
if ($script:fail -eq 0) {
    Write-Host "すべて OK（$($script:count) 件）" -ForegroundColor Green
    Get-Module ADSearch | Remove-Module
    exit 0
}
Write-Host "NG が $($script:fail) 件あります（全 $($script:count) 件）" -ForegroundColor Red
Get-Module ADSearch | Remove-Module
exit 1

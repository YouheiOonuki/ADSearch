# ===========================
# DNS（AD 統合ゾーン）を LDAP で読む。RSAT の DnsServer モジュールの Get-DnsServerZone・Get-DnsServerResourceRecord を再現する。
# 読むだけ。DNS サーバーへの RPC（WMI・DnsServer モジュール）は使わず、ドメイン参加の端末から Domain Users の権限で動く。
#
# AD のどこにあるか（MS-DNSP 2.3）:
#   CN=MicrosoftDNS,DC=DomainDnsZones,<ドメイン NC>   … ドメインの DNS サーバーへ複製（ReplicationScope = Domain）
#   CN=MicrosoftDNS,DC=ForestDnsZones,<ルート NC>     … フォレストの DNS サーバーへ複製（Forest）
#   CN=MicrosoftDNS,CN=System,<ドメイン NC>           … Windows 2000 互換の置き場（Legacy）
#   CN=MicrosoftDNS,<独自のアプリケーション パーティション> … Custom
#   ゾーンは dnsZone（設定は dnsProperty）、レコードはゾーンの下の dnsNode（dnsRecord は DNS_RPC_RECORD の配列）
#
# 取れないもの: AD に入っていないゾーン（ファイルのプライマリ・セカンダリ・自動で作られる 0/127/255.in-addr.arpa）と、
# DNS サーバー自身の設定（フォワーダー・再帰など。サーバーのレジストリにある）
# ===========================

$script:ADSI_DnsTypeNames = @{
    0 = 'ZERO'; 1 = 'A'; 2 = 'NS'; 5 = 'CNAME'; 6 = 'SOA'; 12 = 'PTR'; 13 = 'HINFO'; 15 = 'MX'; 16 = 'TXT'
    17 = 'RP'; 18 = 'AFSDB'; 24 = 'SIG'; 25 = 'KEY'; 28 = 'AAAA'; 33 = 'SRV'; 35 = 'NAPTR'; 39 = 'DNAME'
    43 = 'DS'; 46 = 'RRSIG'; 47 = 'NSEC'; 48 = 'DNSKEY'; 50 = 'NSEC3'; 51 = 'NSEC3PARAM'; 52 = 'TLSA'
    65281 = 'WINS'; 65282 = 'WINSR'
}
$script:ADSI_DnsTypeNumbers = @{}
foreach ($k in $script:ADSI_DnsTypeNames.Keys) { $script:ADSI_DnsTypeNumbers[$script:ADSI_DnsTypeNames[$k]] = $k }

# dnsProperty の Id（MS-DNSP 2.3.2.1.1）
$script:ADSI_DnsZoneTypeNames   = @{ 0 = 'Cache'; 1 = 'Primary'; 2 = 'Secondary'; 3 = 'Stub'; 4 = 'Forwarder'; 5 = 'SecondaryCache' }
$script:ADSI_DnsDynamicUpdate   = @{ 0 = 'None'; 1 = 'NonsecureAndSecure'; 2 = 'Secure' }

# --- バイト列の読み取り（DNS の数はネットワークの順 = ビッグエンディアン） ---
function ADSI_DnsU16BE([byte[]]$B, [int]$Off) { return ([int]$B[$Off] -shl 8) -bor [int]$B[$Off + 1] }
function ADSI_DnsU32BE([byte[]]$B, [int]$Off) {
    return [uint32](([uint32]$B[$Off] -shl 24) -bor ([uint32]$B[$Off + 1] -shl 16) -bor ([uint32]$B[$Off + 2] -shl 8) -bor [uint32]$B[$Off + 3])
}

# DNS_COUNT_NAME（MS-DNSP 2.2.2.2.2）: 長さ 1 + ラベル数 1 + ラベルの並び（長さ付き、0 で終わる）。
# 次の位置は、長さの欄（終わりの 0 を含むかで実装により 1 ずれうる）に頼らず、ラベルを終わりの 0 まで歩いて決める。
# 返す: @{ Name = 'host.corp.local.'; Next = 次の位置 }。名前は RSAT と同じく末尾にドット
function ADSI_DnsReadCountName([byte[]]$B, [int]$Off) {
    if ($Off + 2 -gt $B.Length) { return @{ Name = $null; Next = $B.Length } }
    $count = [int]$B[$Off + 1]
    $pos = $Off + 2
    $labels = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $count -and $pos -lt $B.Length; $i++) {
        $l = [int]$B[$pos]
        if ($l -eq 0) { break }
        $labels.Add([Text.Encoding]::UTF8.GetString($B, $pos + 1, [Math]::Max(0, [Math]::Min($l, $B.Length - $pos - 1))))
        $pos += 1 + $l
    }
    if ($pos -lt $B.Length -and $B[$pos] -eq 0) { $pos++ }   # 終わりの 0
    $name = if ($labels.Count) { ($labels -join '.') + '.' } else { '.' }
    return @{ Name = $name; Next = [Math]::Min($pos, $B.Length) }
}

# DNS_RPC_NAME の並び（TXT）: 長さ 1 + 文字。データの終わりまで
function ADSI_DnsReadTextList([byte[]]$B, [int]$Off, [int]$End) {
    $out = New-Object System.Collections.Generic.List[string]
    $pos = $Off
    while ($pos -lt $End) {
        $l = [int]$B[$pos]
        $out.Add([Text.Encoding]::UTF8.GetString($B, $pos + 1, [Math]::Max(0, [Math]::Min($l, $End - $pos - 1))))
        $pos += 1 + $l
    }
    return , $out.ToArray()
}

function ADSI_DnsHex([byte[]]$B, [int]$Off, [int]$End) {
    if ($End -le $Off) { return '' }
    return (($B[$Off..($End - 1)] | ForEach-Object { '{0:X2}' -f $_ }) -join '')
}

<#
dnsRecord の 1 つ（DNS_RPC_RECORD、MS-DNSP 2.3.2.2）を解く。
  0 DataLength(2, LE) 2 Type(2, LE) 4 Version(1) 5 Rank(1) 6 Flags(2) 8 Serial(4)
  12 TtlSeconds(4, BE) 16 Reserved(4) 20 TimeStamp(4, LE。1601-01-01 からの時間、0 = 静的) 24 Data
返す: @{ Type; RecordType; TimeToLive; Timestamp; RecordData（RSAT の RecordData と同じ名前の欄）; Data（1 行の文字） }
#>
function ADSI_ParseDnsRecord {
    param([byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Length -lt 24) { return $null }
    $dataLen  = [int][BitConverter]::ToUInt16($Bytes, 0)
    $typeNum  = [int][BitConverter]::ToUInt16($Bytes, 2)
    $typeName = $script:ADSI_DnsTypeNames[$typeNum]
    if (-not $typeName) { $typeName = "Type$typeNum" }
    $ttl      = [TimeSpan]::FromSeconds((ADSI_DnsU32BE $Bytes 12))
    $hours    = [BitConverter]::ToUInt32($Bytes, 20)
    $stamp    = if ($hours -eq 0) { $null } else { [DateTime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddHours($hours).ToLocalTime() }
    $d   = 24
    $end = [Math]::Min($Bytes.Length, $d + $dataLen)

    $rd = $null; $text = $null
    switch ($typeNum) {
        1 {   # A
            if ($end - $d -ge 4) { $ip = "$($Bytes[$d]).$($Bytes[$d+1]).$($Bytes[$d+2]).$($Bytes[$d+3])"; $rd = [pscustomobject]@{ IPv4Address = $ip }; $text = $ip }
        }
        28 {  # AAAA
            if ($end - $d -ge 16) {
                [byte[]]$a = $Bytes[$d..($d + 15)]
                $ip = ([System.Net.IPAddress]::new($a)).IPAddressToString
                $rd = [pscustomobject]@{ IPv6Address = $ip }; $text = $ip
            }
        }
        { $_ -in 2, 5, 12, 39 } {  # NS・CNAME・PTR・DNAME: 名前 1 つ
            $n = (ADSI_DnsReadCountName $Bytes $d).Name
            $field = @{ 2 = 'NameServer'; 5 = 'HostNameAlias'; 12 = 'PtrDomainName'; 39 = 'DomainNameAlias' }[$typeNum]
            $rd = [pscustomobject]@{ $field = $n }; $text = $n
        }
        15 {  # MX: 優先度(2, BE) + 名前
            if ($end - $d -ge 3) {
                $pref = ADSI_DnsU16BE $Bytes $d
                $n = (ADSI_DnsReadCountName $Bytes ($d + 2)).Name
                $rd = [pscustomobject]@{ MailExchange = $n; Preference = $pref }; $text = "$pref $n"
            }
        }
        33 {  # SRV: 優先度・重み・ポート(各 2, BE) + 名前
            if ($end - $d -ge 7) {
                $pri = ADSI_DnsU16BE $Bytes $d; $w = ADSI_DnsU16BE $Bytes ($d + 2); $port = ADSI_DnsU16BE $Bytes ($d + 4)
                $n = (ADSI_DnsReadCountName $Bytes ($d + 6)).Name
                $rd = [pscustomobject]@{ DomainName = $n; Port = $port; Priority = $pri; Weight = $w }; $text = "$pri $w $port $n"
            }
        }
        6 {   # SOA: 通番・更新・再試行・期限・最小 TTL(各 4, BE) + 主サーバー + 管理者
            if ($end - $d -ge 22) {
                $serial = ADSI_DnsU32BE $Bytes $d
                $refresh = ADSI_DnsU32BE $Bytes ($d + 4); $retry = ADSI_DnsU32BE $Bytes ($d + 8)
                $expire = ADSI_DnsU32BE $Bytes ($d + 12); $minTtl = ADSI_DnsU32BE $Bytes ($d + 16)
                $p1 = ADSI_DnsReadCountName $Bytes ($d + 20)
                $p2 = ADSI_DnsReadCountName $Bytes $p1.Next
                $rd = [pscustomobject]@{
                    ExpireLimit = [TimeSpan]::FromSeconds($expire); MinimumTimeToLive = [TimeSpan]::FromSeconds($minTtl)
                    PrimaryServer = $p1.Name; RefreshInterval = [TimeSpan]::FromSeconds($refresh)
                    ResponsiblePerson = $p2.Name; RetryDelay = [TimeSpan]::FromSeconds($retry); SerialNumber = $serial
                }
                $text = "[$serial][$($p1.Name)][$($p2.Name)]"
            }
        }
        16 {  # TXT: 文字の並び
            $t = ADSI_DnsReadTextList $Bytes $d $end
            $joined = ($t -join '')
            $rd = [pscustomobject]@{ DescriptiveText = $joined }; $text = $joined
        }
        0 {   # ZERO（消したレコードの印。データは消した時刻の FILETIME）
            $rd = [pscustomobject]@{ Data = (ADSI_DnsHex $Bytes $d $end) }; $text = $null
        }
        default {
            $hex = ADSI_DnsHex $Bytes $d $end
            $rd = [pscustomobject]@{ Data = $hex }; $text = $hex
        }
    }

    @{ Type = $typeNum; RecordType = $typeName; TimeToLive = $ttl; Timestamp = $stamp; RecordData = $rd; Data = $text }
}

<#
dnsProperty の 1 つ（DNS_RPC_PROPERTY、MS-DNSP 2.3.2.1）を解く。
  0 DataLength(4) 4 NameLength(4) 8 Flag(4) 12 Version(4) 16 Id(4) 20 Data
返す: @{ Id; Data（byte[]） }
#>
function ADSI_ParseDnsProperty([byte[]]$Bytes) {
    if ($null -eq $Bytes -or $Bytes.Length -lt 20) { return $null }
    $len = [int][BitConverter]::ToUInt32($Bytes, 0)
    $id  = [int][BitConverter]::ToUInt32($Bytes, 16)
    $len = [Math]::Max(0, [Math]::Min($len, $Bytes.Length - 20))
    [byte[]]$data = if ($len -gt 0) { $Bytes[20..(20 + $len - 1)] } else { @() }
    @{ Id = $id; Data = $data }
}

# IP4_ARRAY（数(4) + IPv4 の並び）
function ADSI_DnsIp4Array([byte[]]$B) {
    if ($null -eq $B -or $B.Length -lt 4) { return @() }
    $n = [BitConverter]::ToUInt32($B, 0)
    $out = @()
    for ($i = 0; $i -lt $n -and (4 + 4 * $i + 3) -lt $B.Length; $i++) {
        $o = 4 + 4 * $i
        $out += "$($B[$o]).$($B[$o+1]).$($B[$o+2]).$($B[$o+3])"
    }
    return , $out
}

# DNS_ADDR_ARRAY（MS-DNSP 2.2.3.2.3）: 頭 32 バイト（AddrCount は 4 バイト目から）+ DNS_ADDR(64 バイト。先頭の 32 バイトが sockaddr)
function ADSI_DnsAddrArray([byte[]]$B) {
    if ($null -eq $B -or $B.Length -lt 32) { return @() }
    $n = [BitConverter]::ToUInt32($B, 4)
    $out = @()
    for ($i = 0; $i -lt $n; $i++) {
        $o = 32 + 64 * $i
        if ($o + 24 -gt $B.Length) { break }
        $fam = [BitConverter]::ToUInt16($B, $o)
        if ($fam -eq 2) { $out += "$($B[$o+4]).$($B[$o+5]).$($B[$o+6]).$($B[$o+7])" }
        elseif ($fam -eq 23) { [byte[]]$a = $B[($o + 8)..($o + 23)]; $out += ([System.Net.IPAddress]::new($a)).IPAddressToString }
    }
    return , $out
}

# dnsProperty の並び → ゾーンの設定（RSAT の Get-DnsServerZone と同じ名前の欄）
function ADSI_DnsZoneSettings($PropertyBlobs) {
    $p = @{}
    foreach ($blob in $PropertyBlobs) {
        $x = ADSI_ParseDnsProperty ([byte[]]$blob)
        if ($x) { $p[$x.Id] = $x.Data }
    }
    # 値の長さは欄ごとに違う（ALLOW_UPDATE は 1 バイト、TYPE・間隔は 4 バイト。MS-DNSP 2.3.2.1.1）。
    # 4 バイト以下の little-endian として読む（1 バイトでも 4 バイトでも同じ値になる）
    $u32 = { param($id)
        if (-not $p.ContainsKey($id) -or $p[$id].Length -lt 1) { return $null }
        $d = $p[$id]; [uint32]$v = 0
        for ($i = [Math]::Min(4, $d.Length) - 1; $i -ge 0; $i--) { $v = ($v -shl 8) -bor $d[$i] }
        $v }
    $type   = & $u32 0x01
    $update = & $u32 0x02
    $noRef  = & $u32 0x10
    $ref    = & $u32 0x20
    $aging  = & $u32 0x40
    $masters = @()
    if ($p.ContainsKey(0x91)) { $masters = ADSI_DnsAddrArray $p[0x91] }
    if (-not $masters.Count -and $p.ContainsKey(0x81)) { $masters = ADSI_DnsIp4Array $p[0x81] }
    $scav = @()
    if ($p.ContainsKey(0x90)) { $scav = ADSI_DnsAddrArray $p[0x90] }
    if (-not $scav.Count -and $p.ContainsKey(0x11)) { $scav = ADSI_DnsIp4Array $p[0x11] }
    [pscustomobject]@{
        ZoneType          = if ($null -ne $type) { $n = $script:ADSI_DnsZoneTypeNames[[int]$type]; if ($n) { $n } else { "Type$type" } } else { 'Primary' }
        DynamicUpdate     = if ($null -ne $update) { $script:ADSI_DnsDynamicUpdate[[int]$update] } else { 'None' }
        Aging             = [bool]($aging)
        NoRefreshInterval = if ($null -ne $noRef) { [TimeSpan]::FromHours($noRef) } else { $null }
        RefreshInterval   = if ($null -ne $ref) { [TimeSpan]::FromHours($ref) } else { $null }
        MasterServers     = $masters
        ScavengeServers   = $scav
    }
}

<#
DNS の置き場（CN=MicrosoftDNS,…）の一覧を、crossRef の並びから組む（純粋な関数。AD に触らない）。
  CrossRefs: @{ NCName; DnsRoot; SystemFlags } の並び（CN=Partitions,<Config> の crossRef）
  Scope Domain: いまのドメイン（DomainDnsZones・System）＋ ForestDnsZones ＋ 独自のパーティション
  Scope Forest: すべてのドメイン
  Partition: All / Both（Domain と Forest。前の版の既定）/ Domain / Forest / Legacy / Custom
返す: @{ Container; Scope(Domain|Forest|Legacy|Custom); PartitionName; NCName; Own(いまのドメインのものか) } の並び
#>
function ADSI_DnsContainerPlan {
    param($CrossRefs, [string]$DomainNC, [string]$RootNC, [ValidateSet('Domain','Forest')][string]$Scope = 'Domain',
          [ValidateSet('All','Both','Domain','Forest','Legacy','Custom')][string]$Partition = 'All')

    $want = switch ($Partition) {
        'All'  { @('Domain', 'Forest', 'Legacy', 'Custom') }
        'Both' { @('Domain', 'Forest') }
        default { @($Partition) }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in $CrossRefs) {
        $nc = [string]$c.NCName; $sf = [int]$c.SystemFlags
        if (-not $nc) { continue }
        $isDomain = ($sf -band 2) -ne 0
        $isApp    = (($sf -band 4) -ne 0) -and -not $isDomain
        if ($isDomain) {
            $own = $nc -ieq $DomainNC
            if ($Scope -eq 'Domain' -and -not $own) { continue }
            if ($want -contains 'Legacy') {
                $out.Add(@{ Container = "CN=MicrosoftDNS,CN=System,$nc"; Scope = 'Legacy'; PartitionName = [string]$c.DnsRoot; NCName = $nc; DnsRoot = [string]$c.DnsRoot; Own = $own })
            }
        }
        elseif ($isApp) {
            if ($nc -match '(?i)^DC=DomainDnsZones,(.+)$') {
                $own = $Matches[1] -ieq $DomainNC
                if ($Scope -eq 'Domain' -and -not $own) { continue }
                $kind = 'Domain'
            }
            elseif ($nc -match '(?i)^DC=ForestDnsZones,(.+)$') { $own = $true; $kind = 'Forest' }
            else { $own = $false; $kind = 'Custom' }
            if ($want -contains $kind) {
                $out.Add(@{ Container = "CN=MicrosoftDNS,$nc"; Scope = $kind; PartitionName = [string]$c.DnsRoot; NCName = $nc; DnsRoot = [string]$c.DnsRoot; Own = $own })
            }
        }
    }
    # 並び: いまのドメイン（Domain → Forest → Legacy）→ Custom → ほかのドメイン（同じ置き場は 1 回）
    $order = @{ Domain = 0; Forest = 1; Legacy = 2; Custom = 3 }
    $rank = { if ($_.Scope -eq 'Custom') { 3 } elseif ($_.Own) { $order[$_.Scope] } else { 4 + $order[$_.Scope] } }
    $seen = @{}
    $out | Sort-Object @{ Expression = $rank }, @{ Expression = { $_.Container } } |
        Where-Object { if ($seen.ContainsKey($_.Container)) { $false } else { $seen[$_.Container] = 1; $true } }
}

# RDN の値をエスケープする（ゾーン名・ノード名を DN に入れるとき）
function ADSI_DnsEscapeRdn([string]$Value) {
    $v = $Value -replace '([,\\+"<>;=])', '\$1'
    if ($v.StartsWith(' ') -or $v.StartsWith('#')) { $v = '\' + $v }
    if ($v.EndsWith(' ')) { $v = $v.Substring(0, $v.Length - 1) + '\ ' }
    return $v
}

# いまの接続から crossRef を読み、置き場の並びを返す
function ADSI_DnsContainers {
    param($Server, [switch]$UseSSL, [pscredential]$Credential, [string]$Scope = 'Domain', [string]$Partition = 'All')

    $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
    $refs = New-Object System.Collections.Generic.List[object]
    $conn = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path "CN=Partitions,$($nc.Config)"
    try {
        $s = ADSI_NewSearcher -SearchRoot $conn -Filter '(objectClass=crossRef)' -Scope OneLevel -Properties @('nCName', 'dnsRoot', 'systemFlags')
        $res = $null
        try {
            $res = $s.FindAll()
            foreach ($r in $res) {
                $p = $r.Properties
                $refs.Add(@{
                    NCName      = if ($p['ncname'].Count) { [string]$p['ncname'][0] } else { '' }
                    DnsRoot     = if ($p['dnsroot'].Count) { [string]$p['dnsroot'][0] } else { '' }
                    SystemFlags = if ($p['systemflags'].Count) { [int]$p['systemflags'][0] } else { 0 }
                })
            }
        }
        finally { if ($res) { $res.Dispose() }; $s.Dispose() }
    }
    finally { $conn.Dispose() }
    # 接続先の DC（RootDSE の dnsHostName）を各置き場に持たせる。-Server を省いたとき、DN だけの serverless では
    # DomainDnsZones などが 0x8007200A で開けない（実機で確認、2026-11-11）ので、いまのドメインの置き場はこの DC で開く
    foreach ($p in (ADSI_DnsContainerPlan -CrossRefs $refs -DomainNC $nc.Default -RootNC $nc.Root -Scope $Scope -Partition $Partition)) {
        $p.DcHost = $nc.DnsHostName
        $p
    }
}

# 置き場ごとの接続先: いまのドメインのものは指定の DC（無ければ RootDSE が答えた DC）、ほかのドメイン・独自のパーティションはその dnsRoot
function ADSI_DnsServerFor($Plan, $Server) {
    if ($Plan.Own -and $Plan.Scope -ne 'Custom') { if ($Server) { return $Server }; return $Plan.DcHost }
    if ($Plan.DnsRoot) { return $Plan.DnsRoot }
    return $Server
}

# 置き場を 1 つ探す（無い・読めない置き場は飛ばす）。結果は 1 件ごとに @{ 属性名（小文字）= 値の配列 } に写して返す
# （byte[] の値はそのまま 1 つの要素。検索の後で Dispose しても値が残るように）
function ADSI_DnsSearchIn {
    param($Plan, $Server, [switch]$UseSSL, [pscredential]$Credential, [string]$Base, [string]$Filter, [string]$SearchScope, [string[]]$Properties)

    $srv = ADSI_DnsServerFor $Plan $Server
    $conn = $null
    # 起点そのものを開けないとき（Domain Users は CN=MicrosoftDNS コンテナの objectClass を読めず、ADSI が 0x8007200A で開けない。
    # 中のゾーン・レコードは読める。実機で確認、2026-11-11）は、パーティションの根元から探し、DN が起点の下にあるものだけを残す
    $within = $null
    try { $conn = New-ADSConnection -Server $srv -UseSSL:$UseSSL -Credential $Credential -Path $Base }
    catch {
        # 無い置き場は $null（見つかって 0 件のときは空の並び）。ゾーンが無いことを呼ぶ側が見分けられるように
        if (ADSI_IsNoSuchObject $_.Exception.Message) { return $null }
        if ($_.Exception.Message -match '0x8007200A' -and $Plan.NCName) {
            try { $conn = New-ADSConnection -Server $srv -UseSSL:$UseSSL -Credential $Credential -Path $Plan.NCName }
            catch {
                Write-Warning "DNS の置き場を読めませんでした（$($Plan.Scope): $Base）: $($_.Exception.Message)"
                return $null
            }
            $within = @{ Base = $Base; OneLevel = ($SearchScope -eq 'OneLevel') }
            $SearchScope = 'Subtree'
            if ($Properties -notcontains 'distinguishedName') { $Properties = @($Properties) + 'distinguishedName' }
        }
        else {
            Write-Warning "DNS の置き場を読めませんでした（$($Plan.Scope): $Base）: $($_.Exception.Message)"
            return $null
        }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $s = ADSI_NewSearcher -SearchRoot $conn -Filter $Filter -Scope $SearchScope -Properties $Properties
        $res = $null
        try {
            $res = $s.FindAll()
            foreach ($r in $res) {
                $h = @{}
                foreach ($a in $Properties) {
                    $k = $a.ToLowerInvariant()
                    $col = $r.Properties[$k]
                    $vals = New-Object System.Collections.Generic.List[object]
                    if ($null -ne $col) { for ($i = 0; $i -lt $col.Count; $i++) { $vals.Add($col[$i]) } }
                    $h[$k] = $vals
                }
                if ($within -and -not (ADSI_DnsUnder ([string]$h['distinguishedname'][0]) $within.Base $within.OneLevel)) { continue }
                $rows.Add($h)
            }
        }
        finally { if ($res) { $res.Dispose() }; $s.Dispose() }
    }
    finally { $conn.Dispose() }
    # 根元から探して 1 件も無ければ、起点（ゾーン）は無いものとみなす（ゾーンは必ず @ のノードを持つ）
    if ($within -and $rows.Count -eq 0) { return $null }
    return , $rows
}

# DN が起点の下にあるか（OneLevel なら直下だけ）。大文字小文字は区別しない
function ADSI_DnsUnder([string]$DN, [string]$Base, [bool]$OneLevel) {
    $suffix = ',' + $Base
    if (-not $DN.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if (-not $OneLevel) { return $true }
    $head = $DN.Substring(0, $DN.Length - $suffix.Length)
    return ([regex]::Split($head, '(?<!\\),').Count -eq 1)   # 直下 = 先頭の RDN が 1 つだけ
}

function ADSI_DnsZoneDisplayName([string]$Name) {
    if ($Name -like '..TrustAnchors') { return 'TrustAnchors' }
    return $Name
}

<#
.SYNOPSIS
AD 統合の DNS ゾーンの一覧（RSAT の Get-DnsServerZone の再現）。
.DESCRIPTION
-ComputerName は DNS サーバーでなく、LDAP で読む DC。-Scope Forest でフォレストのすべてのドメインのゾーンを読む（RSAT には無い拡張）。
消したゾーン（..Deleted-）と作りかけ（..InProgress-）、ルートヒント（RootDNSServers）は出さない。
#>
function Get-DnsServerZone {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [Alias('ZoneName')]
        [string[]]$Name,

        [Alias('Server')]
        [string]$ComputerName,

        [ValidateSet('Domain','Forest')]
        [string]$Scope = 'Domain',

        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        $plans = @(ADSI_DnsContainers -Server $ComputerName -UseSSL:$UseSSL -Credential $Credential -Scope $Scope -Partition 'All')
        $filter = '(objectClass=dnsZone)'
        if ($Name) {
            $or = ($Name | ForEach-Object { "(name=$(ADSI_EscapeLdapValue $_))"; if ($_ -ieq 'TrustAnchors') { '(name=..TrustAnchors)' } }) -join ''
            $filter = "(&$filter(|$or))"
        }
        $emitted = 0
        foreach ($plan in $plans) {
            $rows = ADSI_DnsSearchIn -Plan $plan -Server $ComputerName -UseSSL:$UseSSL -Credential $Credential -Base $plan.Container `
                -Filter $filter -SearchScope OneLevel -Properties @('name', 'dnsProperty', 'distinguishedName', 'whenCreated', 'whenChanged')
            foreach ($p in $rows) {
                if (-not $p['name'].Count) { continue }
                $zn = [string]$p['name'][0]
                if ($zn -like '..Deleted*' -or $zn -like '..InProgress*' -or $zn -ieq 'RootDNSServers') { continue }
                $set = ADSI_DnsZoneSettings $p['dnsproperty']
                $display = ADSI_DnsZoneDisplayName $zn
                $emitted++
                [pscustomobject]@{
                    ZoneName               = $display
                    ZoneType               = $set.ZoneType
                    IsAutoCreated          = $false
                    IsDsIntegrated         = $true
                    IsReverseLookupZone    = [bool]($display -match '(?i)\.(in-addr|ip6)\.arpa$')
                    IsSigned               = $null   # DNSSEC の署名の有無は AD の属性からは決められない
                    DynamicUpdate          = $set.DynamicUpdate
                    ReplicationScope       = $plan.Scope
                    DirectoryPartitionName = $plan.PartitionName
                    Aging                  = $set.Aging
                    NoRefreshInterval      = $set.NoRefreshInterval
                    RefreshInterval        = $set.RefreshInterval
                    MasterServers          = $set.MasterServers
                    ScavengeServers        = $set.ScavengeServers
                    DistinguishedName      = [string]$p['distinguishedname'][0]
                    WhenCreated            = if ($p['whencreated'].Count) { $p['whencreated'][0] } else { $null }
                    WhenChanged            = if ($p['whenchanged'].Count) { $p['whenchanged'][0] } else { $null }
                }
            }
        }
        # RSAT と同じく、名前を指定して 1 つも無ければエラー
        if ($Name -and $emitted -eq 0) { throw "ゾーン '$($Name -join ', ')' が見つかりません（-Scope $Scope の AD 統合ゾーン）" }
    }
    catch {
        ADSI_ThrowLdap $_ 'Get-DnsServerZone に失敗しました'
    }
}

# レコードを読む共通の中身（Get-ADDnsRecord・Get-DnsServerResourceRecord から呼ぶ）。
# 返す: @{ Record（ADSI_ParseDnsRecord の結果）; Zone; Name; DN; WhenChanged; Plan } の並び
function ADSI_DnsRecords {
    param($Server, [switch]$UseSSL, [pscredential]$Credential, [string]$Scope = 'Domain', [string]$Partition = 'All',
          [string]$ZoneName, [string]$Name, [string[]]$RRType, [switch]$IncludeTombstoned,
          [ref]$ZoneFound)   # -ZoneName のゾーンがどこかの置き場にあったか（無ければ $false）

    $plans = @(ADSI_DnsContainers -Server $Server -UseSSL:$UseSSL -Credential $Credential -Scope $Scope -Partition $Partition)
    $filter = '(objectClass=dnsNode)'
    if ($Name) { $filter = ADSI_AndFilters $filter "(name=$(ADSI_EscapeLdapValue $Name))" }
    if (-not $IncludeTombstoned) { $filter = ADSI_AndFilters $filter '(!(dNSTombstoned=TRUE))' }
    $types = $null
    if ($RRType) { $types = @($RRType | ForEach-Object { $_.ToUpperInvariant() }) }

    foreach ($plan in $plans) {
        $zoneRdn = if ($ZoneName) { if ($ZoneName -ieq 'TrustAnchors') { '..TrustAnchors' } else { $ZoneName } } else { $null }
        $base = if ($zoneRdn) { "DC=$(ADSI_DnsEscapeRdn $zoneRdn),$($plan.Container)" } else { $plan.Container }
        $rows = ADSI_DnsSearchIn -Plan $plan -Server $Server -UseSSL:$UseSSL -Credential $Credential -Base $base -Filter $filter `
            -SearchScope Subtree -Properties @('name', 'dnsRecord', 'distinguishedName', 'whenChanged')
        if ($null -ne $rows -and $ZoneFound) { $ZoneFound.Value = $true }
        foreach ($p in $rows) {
            $dn = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { '' }
            $recName = if ($p['name'].Count) { [string]$p['name'][0] } else { '' }
            $when = if ($p['whenchanged'].Count) { $p['whenchanged'][0] } else { $null }
            $zone = ADSI_DnsZoneDisplayName (ADSI_DnsZoneFromDN $dn)
            # dnsRecord はインデックスで 1 つずつ取る（@() で包むと byte[] がバイトに分かれる）
            $col = $p['dnsrecord']
            for ($i = 0; $i -lt $col.Count; $i++) {
                $x = ADSI_ParseDnsRecord ([byte[]]$col[$i])
                if (-not $x) { continue }
                if ($x.Type -eq 0 -and -not $IncludeTombstoned) { continue }
                if ($types -and $types -notcontains $x.RecordType) { continue }
                @{ Record = $x; Zone = $zone; Name = $recName; DN = $dn; WhenChanged = $when; Plan = $plan }
            }
        }
    }
}

function ADSI_DnsZoneFromDN {
    param([string]$DN)

    # DN 例: DC=app1,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local
    # ゾーンは CN=MicrosoftDNS の 1 つ手前の RDN（エスケープした , を含む値でも区切りを誤らない）
    $parts = [regex]::Split($DN, '(?<!\\),')
    for ($i = 1; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ieq 'CN=MicrosoftDNS') {
            return (($parts[$i - 1] -replace '(?i)^DC=', '') -replace '\\(.)', '$1')
        }
    }
    return ''
}

<#
.SYNOPSIS
AD 統合の DNS レコード（ADSearch の名前。ゾーン・DN・変更日つき）。
.DESCRIPTION
-Partition で置き場を選ぶ: All（既定。Domain・Forest・Legacy・Custom）/ Both（Domain と Forest。前の版の既定）/ Domain / Forest / Legacy / Custom。
-Scope Forest でフォレストのすべてのドメイン。消したレコード（dNSTombstoned）は既定で出さない。
#>
function Get-ADDnsRecord {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$ZoneName,
        [ValidateSet('All','Both','Domain','Forest','Legacy','Custom')]
        [string]$Partition = 'All',
        [ValidateSet('Domain','Forest')]
        [string]$Scope = 'Domain',
        [Alias('Type')]
        [string[]]$RRType,
        [switch]$IncludeTombstoned,

        [Alias('Server')]
        [string]$ComputerName,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        foreach ($e in (ADSI_DnsRecords -Server $ComputerName -UseSSL:$UseSSL -Credential $Credential -Scope $Scope -Partition $Partition `
                -ZoneName $ZoneName -Name $Name -RRType $RRType -IncludeTombstoned:$IncludeTombstoned)) {
            [pscustomobject]@{
                ZoneName          = $e.Zone
                Name              = $e.Name
                RecordType        = $e.Record.RecordType
                Data              = $e.Record.Data
                TimeToLive        = $e.Record.TimeToLive
                Timestamp         = $e.Record.Timestamp
                RecordData        = $e.Record.RecordData
                ReplicationScope  = $e.Plan.Scope
                DistinguishedName = $e.DN
                WhenChanged       = $e.WhenChanged
            }
        }
    }
    catch {
        ADSI_ThrowLdap $_ 'Get-ADDnsRecord に失敗しました'
    }
}

<#
.SYNOPSIS
ゾーンのレコード（RSAT の Get-DnsServerResourceRecord の再現）。
.DESCRIPTION
出す欄は RSAT と同じ: HostName・RecordType・Type・Timestamp（静的は空）・TimeToLive・RecordData（型ごとの欄）。
-ComputerName は LDAP で読む DC。-Scope Forest でほかのドメインのゾーンも探す（RSAT には無い拡張）。
#>
function Get-DnsServerResourceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ZoneName,

        [Parameter(Position = 1)]
        [string]$Name,

        [ValidateSet('A','AAAA','CNAME','MX','NS','PTR','SOA','SRV','TXT','DNAME','HINFO','AFSDB','RP','NAPTR','WINS','WINSR','DS','DNSKEY','RRSIG','NSEC','NSEC3','NSEC3PARAM','KEY','SIG','TLSA')]
        [string]$RRType,

        [Alias('Server')]
        [string]$ComputerName,

        [ValidateSet('Domain','Forest')]
        [string]$Scope = 'Domain',

        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        $types = if ($RRType) { @($RRType) } else { $null }
        $found = $false
        foreach ($e in (ADSI_DnsRecords -Server $ComputerName -UseSSL:$UseSSL -Credential $Credential -Scope $Scope -Partition 'All' `
                -ZoneName $ZoneName -Name $Name -RRType $types -ZoneFound ([ref]$found))) {
            [pscustomobject]@{
                HostName   = $e.Name
                RecordType = $e.Record.RecordType
                Type       = $e.Record.Type
                Timestamp  = $e.Record.Timestamp
                TimeToLive = $e.Record.TimeToLive
                RecordData = $e.Record.RecordData
            }
        }
        # RSAT と同じく、無いゾーンはエラーにする（空のゾーンと見分けられるように）
        if (-not $found) { throw "ゾーン '$ZoneName' が見つかりません（-Scope $Scope の AD 統合ゾーン）" }
    }
    catch {
        ADSI_ThrowLdap $_ 'Get-DnsServerResourceRecord に失敗しました'
    }
}

$script:ADSI_DnsTypeNames = @{
    1  = 'A'
    2  = 'NS'
    5  = 'CNAME'
    6  = 'SOA'
    12 = 'PTR'
    15 = 'MX'
    16 = 'TXT'
    28 = 'AAAA'
    33 = 'SRV'
}

function ADSI_ParseDnsRecord {
    param([byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Length -lt 4) { return $null }

    $typeNum  = [int][System.BitConverter]::ToUInt16($Bytes, 2)
    $typeName = $script:ADSI_DnsTypeNames[$typeNum]
    if (-not $typeName) { $typeName = "Type$typeNum" }

    # DNS_RPC_RECORD: 24バイトヘッダー + データ
    # bytes[24..] = レコードデータ
    $data = $null
    switch ($typeNum) {
        1  {  # A record: 4バイト IPv4
            if ($Bytes.Length -ge 28) {
                $data = "$($Bytes[24]).$($Bytes[25]).$($Bytes[26]).$($Bytes[27])"
            }
        }
        28 {  # AAAA record: 16バイト IPv6
            if ($Bytes.Length -ge 40) {
                $data = ([System.Net.IPAddress]::new($Bytes[24..39])).IPAddressToString
            }
        }
    }

    [pscustomobject]@{ Type = $typeName; Data = $data }
}

function ADSI_DnsZoneFromDN {
    param([string]$DN)

    # DN 例: DC=app1,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local
    # 先頭（レコード名）をスキップし、CN=MicrosoftDNS / DC=DomainDnsZones / DC=ForestDnsZones の手前までを zone 名に
    $parts = $DN -split ','
    $zone  = @()

    for ($i = 1; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ieq 'CN=MicrosoftDNS'   -or
            $parts[$i] -ieq 'DC=DomainDnsZones'  -or
            $parts[$i] -ieq 'DC=ForestDnsZones') { break }
        if ($parts[$i] -match '(?i)^DC=') {
            $zone += ($parts[$i] -replace '(?i)^DC=', '')
        }
    }

    $zone -join '.'
}

function Get-ADDnsRecord {
    [CmdletBinding()]
    param(
        [string]$Name,

        [string]$ZoneName,

        # 探索先の DNS アプリケーション パーティション。Both（既定）/ Domain / Forest。
        [ValidateSet('Both','Domain','Forest')]
        [string]$Partition = 'Both',

        [Alias('Server')]
        [string]$ComputerName,

        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        $nc = ADSI_GetNamingContexts -Server $ComputerName -UseSSL:$UseSSL -Credential $Credential

        # DNS レコードは DomainDnsZones と ForestDnsZones のどちらかに存在する。
        # DomainDnsZones はドメイン NC 配下、ForestDnsZones は「フォレストルート NC」配下。
        # 子ドメインでは両者が異なるため、ForestDnsZones は $nc.Root を使う（Default だと存在しない）。
        # -Partition で探索先を限定できる（既定は両方）。
        $domainPart = "DC=DomainDnsZones,$($nc.Default)"
        $forestPart = "DC=ForestDnsZones,$($nc.Root)"
        $partitions = switch ($Partition) {
            'Domain' { @($domainPart) }
            'Forest' { @($forestPart) }
            default  { @($domainPart, $forestPart) }
        }

        $filter = '(objectClass=dnsNode)'
        if ($Name) {
            $filter = ADSI_AndFilters $filter "(name=$(ADSI_EscapeLdapValue $Name))"
        }

        foreach ($partition in $partitions) {
            # ZoneName 指定時は CN=MicrosoftDNS を含む正しいパスでバインド
            $searchBase = if ($ZoneName) { "DC=$ZoneName,CN=MicrosoftDNS,$partition" } else { $partition }

            # バインド失敗（ゾーン/パーティションが存在しない）はスキップ
            $conn = $null
            try {
                $conn = New-ADSConnection -Server $ComputerName -UseSSL:$UseSSL -Credential $Credential -Path $searchBase
            }
            catch {
                if (ADSI_IsNoSuchObject $_.Exception.Message) {
                    continue
                }
                throw
            }

            try {
                $searcher = ADSI_NewSearcher -SearchRoot $conn -Filter $filter `
                    -Properties @('name','dnsRecord','distinguishedName','whenChanged')
                $res = $null
                try {
                    $res = $searcher.FindAll()
                    foreach ($r in $res) {
                        $p           = $r.Properties
                        $dn          = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { '' }
                        $recName     = if ($p['name'].Count)              { [string]$p['name'][0]              } else { '' }
                        $whenChanged = if ($p['whenchanged'].Count)       { $p['whenchanged'][0]               } else { $null }
                        $recZone     = ADSI_DnsZoneFromDN $dn

                        # dnsRecord は ResultPropertyValueCollection をインデックスで直接取得する
                        # @() を使うと byte[] がバイト単位に展開されてしまうため使用禁止
                        $recCol = $p['dnsrecord']
                        if ($null -eq $recCol -or $recCol.Count -eq 0) { continue }

                        for ($i = 0; $i -lt $recCol.Count; $i++) {
                            $blob   = [byte[]]$recCol[$i]
                            $parsed = ADSI_ParseDnsRecord $blob

                            [pscustomobject]@{
                                ZoneName          = $recZone
                                Name              = $recName
                                RecordType        = if ($parsed) { $parsed.Type } else { $null }
                                Data              = if ($parsed) { $parsed.Data } else { $null }
                                DistinguishedName = $dn
                                WhenChanged       = $whenChanged
                            }
                        }
                    }
                }
                finally {
                    if ($res) { $res.Dispose() }
                    $searcher.Dispose()
                }
            }
            finally { $conn.Dispose() }
        }
    }
    catch {
        ADSI_ThrowLdap $_ 'Get-ADDnsRecord に失敗しました'
    }
}

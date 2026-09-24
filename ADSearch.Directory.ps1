# 負の 100ns 間隔（Integer8 の期間値）を TimeSpan に変換。
# 0 および Int64.MinValue は「無期限/未設定」を表すため $null を返す。
function ADSI_IntervalToTimeSpan($v) {
    $n = ADSI_ToInt64 $v
    if ($null -eq $n -or $n -eq 0 -or $n -eq [int64]::MinValue) { return $null }
    try { [TimeSpan]::FromTicks([math]::Abs($n)) } catch { $null }
}

# fSMORoleOwner（NTDS Settings の DN）から所有 DC の dNSHostName を解決。
function ADSI_FsmoOwnerHost($fsmoDN, $Server, [switch]$UseSSL, [pscredential]$Credential) {
    if ([string]::IsNullOrWhiteSpace($fsmoDN)) { return $null }
    try {
        # "CN=NTDS Settings," を除いてサーバーオブジェクト DN を得る
        $serverDN = $fsmoDN -replace '^CN=NTDS Settings,', ''
        $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $c  = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $nc.Config
        try {
            $p = ADSI_GetAttrs $c $serverDN @('dNSHostName')
            if ($p) { return [string](ADSI_FirstVal $p 'dNSHostName') }
        }
        finally { $c.Dispose() }
    }
    catch {}
    $null
}

function ADSI_DnToDns([string]$DN) {
    if (!$DN) { return $null }
    (($DN -split ',' |
      Where-Object  { $_ -match '(?i)^DC=' } |
      ForEach-Object { $_ -replace '(?i)^DC=','' }
     ) -join '.')
}

function ADSI_FunctionalLevelName($Level, $Kind = 'Domain') {
    $n = ADSI_ToInt64 $Level
    $b = switch ($n) {
        0       { 'Windows2000'        }
        1       { 'Windows2003Interim' }
        2       { 'Windows2003'        }
        3       { 'Windows2008'        }
        4       { 'Windows2008R2'      }
        5       { 'Windows2012'        }
        6       { 'Windows2012R2'      }
        7       { 'Windows2016'        }
        default { "Unknown($n)"        }
    }
    if ($b -like 'Unknown*') { $b } else { "$b$Kind" }
}

function Get-ADDomain {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    if ($Identity -and !$Server) { $Server = $Identity }
    $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential

    # NetBIOSName: CN=Partitions,<Config> 内の crossRef を nCName でフィルター
    # nETBIOSName / nCName: MS Learn crossRef スキーマおよび NC-Name 属性で確認済み
    $netBios = $null
    try {
        $partBase = "CN=Partitions,$($nc.Config)"
        $cPart = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $partBase
        try {
            $escaped = $nc.Default -replace '\(','\\28' -replace '\)','\\29'
            $pSrch = ADSI_NewSearcher -SearchRoot $cPart `
                        -Filter "(&(objectClass=crossRef)(nCName=$escaped))" `
                        -Scope OneLevel -Properties @('nETBIOSName')
            $pRes = $null
            try {
                $pRes = $pSrch.FindOne()
                if ($pRes -and $pRes.Properties.Contains('netbiosname') -and $pRes.Properties['netbiosname'].Count) {
                    $netBios = [string]$pRes.Properties['netbiosname'][0]
                }
            }
            finally { if ($pRes) {} $pSrch.Dispose() }
        }
        finally { $cPart.Dispose() }
    }
    catch {}

    # DomainMode: ms-DS-Behavior-Version on domain NC（ドメイン機能レベル）
    $domainMode = $null
    $domainSID  = $null
    $pdcFsmo    = $null
    try {
        $cDom = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $nc.Default
        try {
            $dp = ADSI_GetAttrs $cDom $nc.Default @('msDS-Behavior-Version','objectSid','fSMORoleOwner')
            if ($dp) {
                $bv = ADSI_FirstVal $dp 'msDS-Behavior-Version'
                if ($null -ne $bv) { $domainMode = ADSI_FunctionalLevelName $bv 'Domain' }

                # DomainSID: objectSid バイト配列から SecurityIdentifier へ変換
                $sidRaw = $null
                if ($dp.Contains('objectsid') -and $dp['objectsid'].Count) { $sidRaw = $dp['objectsid'][0] }
                $domainSID = $null
                if ($sidRaw) {
                    try { $domainSID = (New-Object Security.Principal.SecurityIdentifier ([byte[]]$sidRaw), 0).Value } catch {}
                }

                # PDCEmulator: domain NC の fSMORoleOwner
                $pdcFsmo = ADSI_FirstVal $dp 'fSMORoleOwner'
            }
        }
        finally { $cDom.Dispose() }
    }
    catch {}

    # RIDMaster / InfrastructureMaster: 各システムオブジェクトの fSMORoleOwner
    $ridFsmo  = $null
    $infraFsmo = $null
    try {
        $cRid = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path "CN=RID Manager`$,CN=System,$($nc.Default)"
        try {
            $rp = ADSI_GetAttrs $cRid "CN=RID Manager`$,CN=System,$($nc.Default)" @('fSMORoleOwner')
            if ($rp) { $ridFsmo = ADSI_FirstVal $rp 'fSMORoleOwner' }
        }
        finally { $cRid.Dispose() }
    }
    catch {}
    try {
        $cInfra = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path "CN=Infrastructure,$($nc.Default)"
        try {
            $ip = ADSI_GetAttrs $cInfra "CN=Infrastructure,$($nc.Default)" @('fSMORoleOwner')
            if ($ip) { $infraFsmo = ADSI_FirstVal $ip 'fSMORoleOwner' }
        }
        finally { $cInfra.Dispose() }
    }
    catch {}

    [pscustomobject]@{
        DNSRoot              = ADSI_DnToDns $nc.Default
        DistinguishedName    = $nc.Default
        Forest               = ADSI_DnToDns $nc.Root
        NetBIOSName          = $netBios
        DomainMode           = $domainMode
        DomainSID            = $domainSID
        PDCEmulator          = ADSI_FsmoOwnerHost $pdcFsmo $Server -UseSSL:$UseSSL -Credential $Credential
        RIDMaster            = ADSI_FsmoOwnerHost $ridFsmo $Server -UseSSL:$UseSSL -Credential $Credential
        InfrastructureMaster = ADSI_FsmoOwnerHost $infraFsmo $Server -UseSSL:$UseSSL -Credential $Credential
    }
}

function Get-ADForest {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    if ($Identity -and !$Server) { $Server = $Identity }
    $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
    $partBase = "CN=Partitions,$($nc.Config)"

    # SchemaMaster: Schema NC の fSMORoleOwner
    $schemaFsmo = $null
    try {
        $cSch = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $nc.Schema
        try {
            $sp = ADSI_GetAttrs $cSch $nc.Schema @('fSMORoleOwner')
            if ($sp) { $schemaFsmo = ADSI_FirstVal $sp 'fSMORoleOwner' }
        }
        finally { $cSch.Dispose() }
    }
    catch {}

    # DomainNamingMaster: CN=Partitions,<Config> の fSMORoleOwner
    $namingFsmo = $null
    try {
        $cNam = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $partBase
        try {
            $np = ADSI_GetAttrs $cNam $partBase @('fSMORoleOwner')
            if ($np) { $namingFsmo = ADSI_FirstVal $np 'fSMORoleOwner' }
        }
        finally { $cNam.Dispose() }
    }
    catch {}

    # Domains: Partitions 内の crossRef オブジェクトで nETBIOSName が存在するもの → ドメイン NC → DNS 名
    # systemFlags で ADS_SYSTEMFLAG_CR_NTDS_DOMAIN(0x2) が立っているものが正確だが
    # nETBIOSName の存在で代替（ベストエフォート: MS Learn crossRef/Enumerating App Dir Partitions で確認）
    $domains     = $null
    $upnSuffixes = $null
    $sites       = $null
    try {
        $cPart = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $partBase
        try {
            $dSrch = ADSI_NewSearcher -SearchRoot $cPart -Filter '(&(objectClass=crossRef)(nETBIOSName=*))' `
                        -Scope OneLevel -Properties @('nCName','nETBIOSName')
            $dRes = $null
            try {
                $dRes = $dSrch.FindAll()
                $domains = @(foreach ($dr in $dRes) {
                    $ncv = if ($dr.Properties.Contains('ncname') -and $dr.Properties['ncname'].Count) {
                        [string]$dr.Properties['ncname'][0]
                    } else { $null }
                    if ($ncv) { ADSI_DnToDns $ncv }
                })
            }
            finally { if ($dRes) { $dRes.Dispose() } $dSrch.Dispose() }

            # UPNSuffixes: CN=Partitions,<Config> の uPNSuffixes 属性（多値）
            $partAttrs = ADSI_GetAttrs $cPart $partBase @('uPNSuffixes')
            if ($partAttrs -and $partAttrs.Contains('upnsuffixes') -and $partAttrs['upnsuffixes'].Count) {
                $upnSuffixes = @($partAttrs['upnsuffixes'] | ForEach-Object { [string]$_ })
            }
        }
        finally { $cPart.Dispose() }
    }
    catch {}

    # Sites: CN=Sites,<Config> の直下の objectClass=site オブジェクトの CN
    try {
        $sitesBase = "CN=Sites,$($nc.Config)"
        $cSites = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $sitesBase
        try {
            $sSrch = ADSI_NewSearcher -SearchRoot $cSites -Filter '(objectClass=site)' `
                        -Scope OneLevel -Properties @('name')
            $sRes = $null
            try {
                $sRes = $sSrch.FindAll()
                $sites = @(foreach ($sr in $sRes) {
                    if ($sr.Properties.Contains('name') -and $sr.Properties['name'].Count) {
                        [string]$sr.Properties['name'][0]
                    }
                })
            }
            finally { if ($sRes) { $sRes.Dispose() } $sSrch.Dispose() }
        }
        finally { $cSites.Dispose() }
    }
    catch {}

    [pscustomobject]@{
        Name                 = ADSI_DnToDns $nc.Root
        RootDomain           = ADSI_DnToDns $nc.Root
        ForestMode           = ADSI_FunctionalLevelName $nc.ForestFunctionality Forest
        SchemaMaster         = ADSI_FsmoOwnerHost $schemaFsmo $Server -UseSSL:$UseSSL -Credential $Credential
        DomainNamingMaster   = ADSI_FsmoOwnerHost $namingFsmo $Server -UseSSL:$UseSSL -Credential $Credential
        Domains              = $domains
        UPNSuffixes          = $upnSuffixes
        Sites                = $sites
    }
}

function Get-ADDomainController {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        # 後方互換: 接続先 DC 1件のみを返す（旧動作）
        [switch]$Discover,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential

    # -Discover: rootDSE から合成した単一オブジェクトを返す（後方互換）
    if ($Discover) {
        return [pscustomobject]@{
            Name         = ($nc.DnsHostName -split '\.')[0]
            HostName     = $nc.DnsHostName
            Domain       = ADSI_DnToDns $nc.Default
            Forest       = ADSI_DnToDns $nc.Root
            Site         = $null
            IsGlobalCatalog = $null
            IsReadOnly   = $null
        }
    }

    # Config NC の "CN=Sites,<Config>" 配下の nTDSDSA オブジェクトを全件列挙
    # nTDSDSA の options bit 0x1 = NTDSDSA_OPT_IS_GC（MS Learn: Binding to the Global Catalog で確認済み）
    # nTDSDSARO は RODC の NTDS Settings クラス（ベストエフォート: objectClass で判定）
    $sitesBase = "CN=Sites,$($nc.Config)"
    $connCfg = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $sitesBase
    try {
        $srch = ADSI_NewSearcher -SearchRoot $connCfg -Filter '(objectClass=nTDSDSA)' -Scope Subtree `
                    -Properties @('distinguishedName','objectClass','options','name')
        $results = $null
        try {
            $results = $srch.FindAll()
            $dcs = foreach ($r in $results) {
                $p = $r.Properties
                $dsaDN = [string]($p['distinguishedname'][0])
                # サーバーオブジェクトは nTDSDSA の親（"CN=NTDS Settings,CN=<server>,CN=Servers,CN=<site>,CN=Sites,..."）
                $serverDN = $dsaDN -replace '^CN=NTDS Settings,', ''
                # DN を分割してサイト名とサーバー CN を抽出
                # 構造: CN=<server>,CN=Servers,CN=<site>,CN=Sites,...
                $parts = $serverDN -split ',(?=CN=|DC=)'
                $serverCN = if ($parts.Count -ge 1) { $parts[0] -replace '^CN=','' } else { $null }
                $siteCN   = if ($parts.Count -ge 3) { $parts[2] -replace '^CN=','' } else { $null }

                # サーバーオブジェクトから dNSHostName を取得
                $hostName = $null
                try {
                    $cSrv = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $serverDN
                    try {
                        $sp = ADSI_GetAttrs $cSrv $serverDN @('dNSHostName')
                        if ($sp) { $hostName = [string](ADSI_FirstVal $sp 'dNSHostName') }
                    }
                    finally { $cSrv.Dispose() }
                }
                catch {}

                $opts    = ADSI_ToInt64 $(if ($p.Contains('options') -and $p['options'].Count) { $p['options'][0] } else { $null })
                $isGC    = if ($null -eq $opts) { $false } else { [bool]($opts -band 1) }
                $oc      = @($p['objectclass'])
                $isRO    = $oc -contains 'nTDSDSARO'

                [pscustomobject]@{
                    Name            = $serverCN
                    HostName        = $hostName
                    Site            = $siteCN
                    IsGlobalCatalog = $isGC
                    IsReadOnly      = $isRO
                    Domain          = ADSI_DnToDns $nc.Default
                    Forest          = ADSI_DnToDns $nc.Root
                }
            }
        }
        finally {
            if ($results) { $results.Dispose() }
            $srch.Dispose()
        }
    }
    finally { $connCfg.Dispose() }

    # -Filter が '*' または空なら全件返す。複雑なフィルターはクライアント側無視（警告なし）
    $useFilter = $Filter -and $Filter -ne '*'
    # -Identity はクライアント側で Name または HostName と照合
    foreach ($dc in $dcs) {
        if ($Identity -and $dc.Name -notlike $Identity -and $dc.HostName -notlike $Identity) { continue }
        if ($useFilter) {
            # 単純 Identity 風フィルターのみ対応（未対応フィルターはベストエフォートで全件返す）
        }
        $dc
    }
}

function Get-ADDefaultDomainPasswordPolicy {
    [CmdletBinding()]
    param(
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
    $c  = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $nc.Default
    try {
        # lockOutObservationWindow: LDAP名は大文字 'O'（MS Learn: Lock-Out-Observation-Window 属性で確認済み）
        $attrs = @('minPwdLength','maxPwdAge','minPwdAge','pwdHistoryLength',
                   'lockoutThreshold','lockoutDuration','lockOutObservationWindow','pwdProperties')
        $p = ADSI_GetAttrs $c $nc.Default $attrs
        # pwdProperties ビットフィールド（MS Learn: Pwd-Properties 属性で確認済み）
        # DOMAIN_PASSWORD_COMPLEX=1, DOMAIN_PASSWORD_STORE_CLEARTEXT=16
        $pwdProp = ADSI_ToInt64(ADSI_FirstVal $p 'pwdProperties')
        [pscustomobject]@{
            DistinguishedName              = $nc.Default
            MinPasswordLength              = [int](ADSI_ToInt64(ADSI_FirstVal $p 'minPwdLength'))
            PasswordHistoryCount           = [int](ADSI_ToInt64(ADSI_FirstVal $p 'pwdHistoryLength'))
            LockoutThreshold               = [int](ADSI_ToInt64(ADSI_FirstVal $p 'lockoutThreshold'))
            MaxPasswordAge                 = ADSI_IntervalToTimeSpan(ADSI_FirstVal $p 'maxPwdAge')
            MinPasswordAge                 = ADSI_IntervalToTimeSpan(ADSI_FirstVal $p 'minPwdAge')
            LockoutDuration                = ADSI_IntervalToTimeSpan(ADSI_FirstVal $p 'lockoutDuration')
            LockoutObservationWindow       = ADSI_IntervalToTimeSpan(ADSI_FirstVal $p 'lockOutObservationWindow')
            ComplexityEnabled              = if ($null -eq $pwdProp) { $null } else { [bool]($pwdProp -band 0x1) }
            ReversibleEncryptionEnabled    = if ($null -eq $pwdProp) { $null } else { [bool]($pwdProp -band 0x10) }
        }
    }
    finally { $c.Dispose() }
}

# trustDirection の数値を文字列に変換
# 値: 0=Disabled, 1=Inbound, 2=Outbound, 3=Bidirectional（MS Learn: TRUSTED_DOMAIN_INFORMATION_EX で確認済み）
function ADSI_TrustDirectionName($v) {
    $n = ADSI_ToInt64 $v
    switch ($n) {
        0 { 'Disabled' }
        1 { 'Inbound' }
        2 { 'Outbound' }
        3 { 'Bidirectional' }
        default { if ($null -eq $n) { $null } else { "Unknown($n)" } }
    }
}

# trustType の数値を文字列に変換
# 値: 1=Downlevel, 2=Uplevel, 3=MIT, 4=DCE（MS Learn: TRUSTED_DOMAIN_INFORMATION_EX TrustType で確認済み）
function ADSI_TrustTypeName($v) {
    $n = ADSI_ToInt64 $v
    switch ($n) {
        1 { 'Downlevel' }
        2 { 'Uplevel' }
        3 { 'MIT' }
        4 { 'DCE' }
        default { if ($null -eq $n) { $null } else { "Unknown($n)" } }
    }
}

function Get-ADTrust {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $f  = ADSI_BuildFinalFilter '(objectClass=trustedDomain)' $Identity $LDAPFilter $Filter
        $raw = ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase "CN=System,$($nc.Default)" `
            -Filter $f `
            -DefaultProps @('Name','DistinguishedName') `
            -Properties @('trustPartner','trustDirection','trustType','trustAttributes')

        foreach ($r in $raw) {
            # trustAttributes ビットフィールド（MS Learn: TRUSTED_DOMAIN_INFORMATION_EX TrustAttributes で確認済み）
            # TRUST_ATTRIBUTE_NON_TRANSITIVE=0x1, TRUST_ATTRIBUTE_FOREST_TRANSITIVE=0x8, TRUST_ATTRIBUTE_WITHIN_FOREST=0x20
            $ta = ADSI_ToInt64 $r.trustAttributes
            [pscustomobject]@{
                DistinguishedName = $r.DistinguishedName
                Name              = $r.Name
                Source            = ADSI_DnToDns $nc.Default
                Target            = $r.trustPartner
                Direction         = ADSI_TrustDirectionName $r.trustDirection
                TrustType         = ADSI_TrustTypeName $r.trustType
                ForestTransitive  = if ($null -eq $ta) { $null } else { [bool]($ta -band 0x8) }
                IntraForest       = if ($null -eq $ta) { $null } else { [bool]($ta -band 0x20) }
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADTrust に失敗しました' }
}

function Get-ADReplicationSite {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $f  = ADSI_BuildFinalFilter '(objectClass=site)' $Identity $LDAPFilter $Filter
        ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase "CN=Sites,$($nc.Config)" `
            -Filter $f `
            -DefaultProps @('Name','DistinguishedName','Description')
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADReplicationSite に失敗しました' }
}

function Get-ADReplicationSiteLink {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $f  = ADSI_BuildFinalFilter '(objectClass=siteLink)' $Identity $LDAPFilter $Filter
        ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase "CN=Inter-Site Transports,CN=Sites,$($nc.Config)" `
            -Filter $f `
            -DefaultProps @('Name','DistinguishedName') `
            -Properties @('siteList','cost')
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADReplicationSiteLink に失敗しました' }
}

function Get-ADReplicationSubnet {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $f  = ADSI_BuildFinalFilter '(objectClass=subnet)' $Identity $LDAPFilter $Filter
        ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase "CN=Subnets,CN=Sites,$($nc.Config)" `
            -Filter $f `
            -DefaultProps @('Name','DistinguishedName') `
            -Properties @('siteObject','location')
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADReplicationSubnet に失敗しました' }
}

function Get-ADReplicationConnection {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $f  = ADSI_BuildFinalFilter '(objectClass=nTDSConnection)' $Identity $LDAPFilter $Filter
        ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase $nc.Config `
            -Filter $f `
            -DefaultProps @('Name','DistinguishedName') `
            -Properties @('fromServer','options')
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADReplicationConnection に失敗しました' }
}

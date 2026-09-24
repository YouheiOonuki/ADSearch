try { Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop } catch {}

$script:ADSI_DefaultProperties = @{
    # SID・ObjectGUID は RSAT の既定出力に含まれるため追加（既存スクリプト互換）
    User           = @('DistinguishedName','Name','SamAccountName','UserPrincipalName','DisplayName','EmailAddress','Enabled','LockedOut','PasswordExpired','AccountExpirationDate','LastLogonDate','PasswordLastSet','MemberOf','ObjectClass','SID','ObjectGUID')
    Group          = @('DistinguishedName','Name','SamAccountName','GroupScope','GroupCategory','Description','Member','MemberOf','ObjectGUID','SID','ObjectClass')
    Computer       = @('DistinguishedName','Name','SamAccountName','DNSHostName','OperatingSystem','Enabled','LastLogonDate','PasswordLastSet','MachinePasswordAge','IPv4Address','ObjectGUID','SID','ObjectClass')
    OU             = @('DistinguishedName','Name','Description','Created','Modified','ObjectGUID','ObjectClass','LinkedGroupPolicyObjects')
    Object         = @('DistinguishedName','Name','ObjectClass','ObjectGUID','SID','Created','Modified')
    ServiceAccount = @('DistinguishedName','Name','SamAccountName','DNSHostName','Enabled','ObjectGUID','SID','ObjectClass')
}

$script:ADSI_OutputDefs = @{
    DistinguishedName = @{ Ldap = 'distinguishedName';  Kind = 'direct'    }
    Name              = @{ Ldap = 'name';               Kind = 'direct'    }
    SamAccountName    = @{ Ldap = 'sAMAccountName';     Kind = 'direct'    }
    UserPrincipalName = @{ Ldap = 'userPrincipalName';  Kind = 'direct'    }
    DisplayName       = @{ Ldap = 'displayName';        Kind = 'direct'    }
    EmailAddress      = @{ Ldap = 'mail';               Kind = 'direct'    }
    Description       = @{ Ldap = 'description';        Kind = 'direct'    }
    Member            = @{ Ldap = 'member';             Kind = 'direct'    }
    MemberOf          = @{ Ldap = 'memberOf';           Kind = 'direct'    }
    DNSHostName       = @{ Ldap = 'dNSHostName';        Kind = 'direct'    }
    OperatingSystem   = @{ Ldap = 'operatingSystem';    Kind = 'direct'    }
    ObjectClass       = @{ Ldap = 'objectClass';        Kind = 'lastvalue' }
    ObjectGUID        = @{ Ldap = 'objectGUID';         Kind = 'guid'      }
    SID               = @{ Ldap = 'objectSid';          Kind = 'sid'       }
    Enabled           = @{ Ldap = 'userAccountControl'; Kind = 'uac'       }
    LastLogonDate     = @{ Ldap = 'lastLogonTimestamp'; Kind = 'filetime'  }
    PasswordLastSet   = @{ Ldap = 'pwdLastSet';         Kind = 'filetime'  }
    Created           = @{ Ldap = 'whenCreated';        Kind = 'direct'    }
    Modified          = @{ Ldap = 'whenChanged';        Kind = 'direct'    }
    GroupScope        = @{ Ldap = 'groupType';          Kind = 'scope'     }
    GroupCategory     = @{ Ldap = 'groupType';          Kind = 'cat'       }
    IPv4Address       = @{ Ldap = 'dNSHostName';        Kind = 'ipv4'      }
    # アカウント状態系（ログイントラブルの切り分け用）。
    # LockedOut / PasswordExpired は DC が計算する構築属性 msDS-User-Account-Control-Computed
    # から判定するため、ドメインポリシー照会なしで正確に取れる（RSAT と同方式）。
    AccountExpirationDate = @{ Ldap = 'accountExpires';                       Kind = 'filetime'    }
    LockedOut             = @{ Ldap = 'msDS-User-Account-Control-Computed';   Kind = 'lockedout'   }
    PasswordExpired       = @{ Ldap = 'msDS-User-Account-Control-Computed';   Kind = 'pwdexpired'  }
    PasswordNeverExpires  = @{ Ldap = 'userAccountControl';                   Kind = 'pwdneverexp' }
    PasswordExpiryDate    = @{ Ldap = 'msDS-UserPasswordExpiryTimeComputed';  Kind = 'filetime'    }
    # マシンアカウントのパスワード経過日数（>30 でセキュアチャネル切れ＝信頼関係失敗の疑い）
    MachinePasswordAge    = @{ Ldap = 'pwdLastSet';                           Kind = 'agedays'     }

    # ---------------------------------------------------------------
    # RSAT 互換プロパティ（-Properties で明示指定して使用）
    # ユーザー個人情報系
    # ---------------------------------------------------------------
    GivenName            = @{ Ldap = 'givenName';                    Kind = 'direct'   }
    Surname              = @{ Ldap = 'sn';                           Kind = 'direct'   }
    Initials             = @{ Ldap = 'initials';                     Kind = 'direct'   }
    Title                = @{ Ldap = 'title';                        Kind = 'direct'   }
    Department           = @{ Ldap = 'department';                   Kind = 'direct'   }
    Company              = @{ Ldap = 'company';                      Kind = 'direct'   }
    Manager              = @{ Ldap = 'manager';                      Kind = 'direct'   }
    Office               = @{ Ldap = 'physicalDeliveryOfficeName';   Kind = 'direct'   }
    Division             = @{ Ldap = 'division';                     Kind = 'direct'   }
    Organization         = @{ Ldap = 'o';                            Kind = 'direct'   }
    EmployeeID           = @{ Ldap = 'employeeID';                   Kind = 'direct'   }
    EmployeeNumber       = @{ Ldap = 'employeeNumber';               Kind = 'direct'   }
    # 連絡先
    OfficePhone          = @{ Ldap = 'telephoneNumber';              Kind = 'direct'   }
    MobilePhone          = @{ Ldap = 'mobile';                       Kind = 'direct'   }
    HomePhone            = @{ Ldap = 'homePhone';                    Kind = 'direct'   }
    Fax                  = @{ Ldap = 'facsimileTelephoneNumber';     Kind = 'direct'   }
    # 住所
    StreetAddress        = @{ Ldap = 'streetAddress';                Kind = 'direct'   }
    City                 = @{ Ldap = 'l';                            Kind = 'direct'   }
    State                = @{ Ldap = 'st';                           Kind = 'direct'   }
    PostalCode           = @{ Ldap = 'postalCode';                   Kind = 'direct'   }
    Country              = @{ Ldap = 'c';                            Kind = 'direct'   }
    POBox                = @{ Ldap = 'postOfficeBox';                Kind = 'direct'   }
    # プロファイル・ログオンスクリプト
    HomeDirectory        = @{ Ldap = 'homeDirectory';                Kind = 'direct'   }
    HomeDrive            = @{ Ldap = 'homeDrive';                    Kind = 'direct'   }
    ProfilePath          = @{ Ldap = 'profilePath';                  Kind = 'direct'   }
    ScriptPath           = @{ Ldap = 'scriptPath';                   Kind = 'direct'   }
    # ログオン統計
    LogonCount           = @{ Ldap = 'logonCount';                   Kind = 'direct'   }
    BadLogonCount        = @{ Ldap = 'badPwdCount';                  Kind = 'direct'   }
    # Exchange / プロキシ
    ProxyAddresses       = @{ Ldap = 'proxyAddresses';               Kind = 'direct'   }
    PrimaryGroupID       = @{ Ldap = 'primaryGroupID';               Kind = 'direct'   }
    # filetime 系
    LastBadPasswordAttempt = @{ Ldap = 'badPasswordTime';            Kind = 'filetime' }
    AccountLockoutTime     = @{ Ldap = 'lockoutTime';                Kind = 'filetime' }
    # userAccountControl ビットフラグ（新 Kind）
    # bit 0x20      = PASSWD_NOTREQD
    # bit 0x40000   = SMARTCARD_REQUIRED
    # bit 0x80000   = TRUSTED_FOR_DELEGATION
    PasswordNotRequired      = @{ Ldap = 'userAccountControl'; Kind = 'pwdnotreq'    }
    SmartcardLogonRequired   = @{ Ldap = 'userAccountControl'; Kind = 'smartcardreq' }
    TrustedForDelegation     = @{ Ldap = 'userAccountControl'; Kind = 'trusteddeleg' }
    # ---------------------------------------------------------------
    # RSAT 互換プロパティ（コンピューター用）
    # ---------------------------------------------------------------
    OperatingSystemVersion     = @{ Ldap = 'operatingSystemVersion';     Kind = 'direct' }
    OperatingSystemServicePack = @{ Ldap = 'operatingSystemServicePack'; Kind = 'direct' }
    Location                   = @{ Ldap = 'location';                   Kind = 'direct' }
    ManagedBy                  = @{ Ldap = 'managedBy';                  Kind = 'direct' }
    ServicePrincipalName       = @{ Ldap = 'servicePrincipalName';       Kind = 'direct' }
    # IPv6Address: dNSHostName を DNS 解決して InterNetworkV6 アドレスを返す
    IPv6Address                = @{ Ldap = 'dNSHostName';                Kind = 'ipv6'   }
    # OU に適用された GPO の DN リスト（gPLink 文字列をパースして返す）
    LinkedGroupPolicyObjects   = @{ Ldap = 'gPLink';                     Kind = 'gplink' }
}

$script:ADSI_FilterAlias = @{
    distinguishedname = 'distinguishedName'
    name              = 'name'
    cn                = 'cn'
    samaccountname    = 'sAMAccountName'
    userprincipalname = 'userPrincipalName'
    upn               = 'userPrincipalName'
    displayname       = 'displayName'
    emailaddress      = 'mail'
    mail              = 'mail'
    memberof          = 'memberOf'
    member            = 'member'
    dnshostname       = 'dNSHostName'
    objectclass       = 'objectClass'
    objectcategory    = 'objectCategory'
    objectguid        = 'objectGUID'
    sid               = 'objectSid'
    enabled           = 'userAccountControl'
    # RSAT 互換フィルターエイリアス（サーバー側フィルタリングが可能な直接属性のみ）
    givenname         = 'givenName'
    surname           = 'sn'
    sn                = 'sn'
    initials          = 'initials'
    title             = 'title'
    department        = 'department'
    company           = 'company'
    manager           = 'manager'
    office            = 'physicalDeliveryOfficeName'
    division          = 'division'
    organization      = 'o'
    employeeid        = 'employeeID'
    employeenumber    = 'employeeNumber'
    officephone       = 'telephoneNumber'
    telephonenumber   = 'telephoneNumber'
    mobilephone       = 'mobile'
    mobile            = 'mobile'
    homephone         = 'homePhone'
    fax               = 'facsimileTelephoneNumber'
    streetaddress     = 'streetAddress'
    city              = 'l'
    state             = 'st'
    postalcode        = 'postalCode'
    country           = 'c'
    pobox             = 'postOfficeBox'
    homedirectory     = 'homeDirectory'
    homedrive         = 'homeDrive'
    profilepath       = 'profilePath'
    scriptpath        = 'scriptPath'
    proxyaddresses    = 'proxyAddresses'
    primarygroupid    = 'primaryGroupID'
    location          = 'location'
    managedby         = 'managedBy'
    serviceprincipalname = 'servicePrincipalName'
    operatingsystem              = 'operatingSystem'
    operatingsystemversion       = 'operatingSystemVersion'
    operatingsystemservicepack   = 'operatingSystemServicePack'
}

function ADSI_ToInt64($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [int64]) { return $v }
    if ($v -is [int])   { return [int64]$v }
    if ($v -is [string]) {
        $o = 0L
        if ([int64]::TryParse($v, [ref]$o)) { return $o }
        return $null
    }
    try {
        $t = $v.GetType()
        $h = [int64]$t.InvokeMember('HighPart', 'GetProperty', $null, $v, $null)
        $l = [int64]$t.InvokeMember('LowPart',  'GetProperty', $null, $v, $null)
        (($h -shl 32) -bor ($l -band 0xffffffffL))
    }
    catch {
        try { [int64]$v } catch { $null }
    }
}

# gPLink 文字列（"[LDAP://<gpoDN>;<flags>][LDAP://<gpoDN>;<flags>]..."）から GPO DN 配列を返す。
# 空文字列・未設定時は @() を返す。
function ADSI_ParseGpLink($v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return @() }
    $s = [string]$v
    $matches = [System.Text.RegularExpressions.Regex]::Matches($s, '\[LDAP://([^;]+);[^\]]+\]', 'IgnoreCase')
    if ($matches.Count -eq 0) { return @() }
    @($matches | ForEach-Object { $_.Groups[1].Value })
}

function ADSI_FileTimeToDate($v) {
    $f = ADSI_ToInt64 $v
    if ($null -eq $f -or $f -eq 0 -or $f -eq 9223372036854775807) { return $null }
    try { [DateTime]::FromFileTimeUtc($f).ToLocalTime() } catch { $null }
}

function ADSI_UacToEnabled($u) {
    $x = ADSI_ToInt64 $u
    if ($null -eq $x) { return $null }
    -not [bool]($x -band 2)
}

# ビットフラグ判定（userAccountControl / msDS-User-Account-Control-Computed 用）
function ADSI_HasFlag($v, [int64]$bit) {
    $x = ADSI_ToInt64 $v
    if ($null -eq $x) { return $null }
    [bool]($x -band $bit)
}

# FileTime から現在までの経過日数（マシンパスワード鮮度の判定用）
function ADSI_AgeInDays($v) {
    $d = ADSI_FileTimeToDate $v
    if ($null -eq $d) { return $null }
    [int]((Get-Date) - $d).TotalDays
}

function ADSI_GroupScope($g) {
    $x = ADSI_ToInt64 $g
    if ($null -eq $x) { return $null }
    if ($x -band 8)        { 'Universal'   }
    elseif ($x -band 4)    { 'DomainLocal' }
    elseif ($x -band 2)    { 'Global'      }
    else                   { 'Unknown'     }
}

function ADSI_GroupCategory($g) {
    $x = ADSI_ToInt64 $g
    if ($null -eq $x) { return $null }
    if ($x -band 0x80000000L) { 'Security' } else { 'Distribution' }
}

function ADSI_ResolveIPv4($h) {
    if ([string]::IsNullOrWhiteSpace($h)) { return $null }
    try {
        $a = [System.Net.Dns]::GetHostAddresses($h) |
             Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
             Select-Object -First 1
        if ($a) { $a.IPAddressToString }
    }
    catch { $null }
}

# ADSI_ResolveIPv4 と対で IPv6 アドレスを返す（InterNetworkV6 アドレスファミリのみ）
function ADSI_ResolveIPv6($h) {
    if ([string]::IsNullOrWhiteSpace($h)) { return $null }
    try {
        $a = [System.Net.Dns]::GetHostAddresses($h) |
             Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 } |
             Select-Object -First 1
        if ($a) { $a.IPAddressToString }
    }
    catch { $null }
}

function ADSI_FirstVal($p, [string]$n) {
    $k = $n.ToLowerInvariant()
    if ($p.Contains($k) -and $p[$k].Count) { return $p[$k][0] }
    if ($p.Contains($n) -and $p[$n].Count) { return $p[$n][0] }
    $null
}

function ADSI_ReadConverted($p, [string]$n, [string]$kind = 'auto') {
    $k = $n.ToLowerInvariant()
    $v = @()
    if      ($p.Contains($k)) { $v = @($p[$k]) }
    elseif  ($p.Contains($n)) { $v = @($p[$n]) }
    if (!$v.Count) { return $null }
    switch ($kind) {
        # RSAT と同型（Guid オブジェクト）で返す
        guid    { try { New-Object Guid (,[byte[]]$v[0]) } catch { $null } }
        # RSAT と同型（SecurityIdentifier オブジェクト）で返す
        sid     { try { New-Object Security.Principal.SecurityIdentifier ([byte[]]$v[0]), 0 } catch { $null } }
        default { if ($v.Count -eq 1) { $v[0] } else { ,@($v) } }
    }
}

function ADSI_GetAuthTypes([switch]$UseSSL) {
    $a = [DirectoryServices.AuthenticationTypes]::Secure
    if ($UseSSL) { $a = $a -bor [DirectoryServices.AuthenticationTypes]::SecureSocketsLayer }
    $a
}

function ADSI_MakeLdapPath($Server, $Path, [switch]$UseSSL) {
    $s = $Server
    if ($UseSSL -and $s -and $s -notmatch ':\d+$') { $s = "$s`:636" }
    if ($s) { "LDAP://$s/$Path" } else { "LDAP://$Path" }
}

function ADSI_GetRootDSE {
    param(
        $Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    if ($UseSSL -and [string]::IsNullOrWhiteSpace($Server)) {
        throw '-UseSSL には -Server の指定が必要です（serverless バインドは LDAPS 非対応）'
    }

    $path = ADSI_MakeLdapPath $Server RootDSE -UseSSL:$UseSSL
    $auth = ADSI_GetAuthTypes -UseSSL:$UseSSL
    try {
        if ($Credential) {
            $d = New-Object DirectoryServices.DirectoryEntry(
                    $path,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password,
                    $auth)
        }
        else {
            $d = New-Object DirectoryServices.DirectoryEntry($path)
            $d.AuthenticationType = $auth
        }
        [void]$d.Properties['defaultNamingContext'].Value
        $d
    }
    catch {
        throw "RootDSE取得に失敗しました (Path='$path'): $($_.Exception.Message)"
    }
}

function ADSI_GetNamingContexts {
    param(
        $Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    $r = ADSI_GetRootDSE -Server $Server -UseSSL:$UseSSL -Credential $Credential
    try {
        [pscustomobject]@{
            Default             = [string]$r.Properties['defaultNamingContext'].Value
            Config              = [string]$r.Properties['configurationNamingContext'].Value
            Schema              = [string]$r.Properties['schemaNamingContext'].Value
            Root                = [string]$r.Properties['rootDomainNamingContext'].Value
            DnsHostName         = [string]$r.Properties['dnsHostName'].Value
            ForestFunctionality = $r.Properties['forestFunctionality'].Value
        }
    }
    finally { $r.Dispose() }
}

# bind/検索時の「オブジェクトが存在しない」エラー判定（ロケール非依存）。
# 日本語/英語のメッセージ表現に加え、no-such-object の HRESULT 0x80072030 でも判定する。
function ADSI_IsNoSuchObject([string]$message) {
    if ([string]::IsNullOrEmpty($message)) { return $false }
    return [bool](
        $message -match '0x80072030' -or
        $message -match '(?i)no such object' -or
        $message -match 'そのようなオブジェクト' -or
        $message -match '存在しません'
    )
}

function New-ADSConnection {
    param(
        $Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        $Path,
        [ValidateSet('Default','Config','Schema','RootDSE','ForestDns')]
        $NamingContext = 'Default'
    )

    if ($UseSSL -and [string]::IsNullOrWhiteSpace($Server)) {
        throw '-UseSSL には -Server の指定が必要です（serverless バインドは LDAPS 非対応）'
    }

    try {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
            switch ($NamingContext) {
                Config    { $Path = $nc.Config  }
                Schema    { $Path = $nc.Schema  }
                RootDSE   { $Path = 'RootDSE'   }
                ForestDns { $Path = $nc.Root    }
                default   { $Path = $nc.Default }
            }
            if (!$Server) { $Server = $nc.DnsHostName }
        }

        $ldap = ADSI_MakeLdapPath $Server $Path -UseSSL:$UseSSL
        $auth = ADSI_GetAuthTypes -UseSSL:$UseSSL

        if ($Credential) {
            $d = New-Object DirectoryServices.DirectoryEntry(
                    $ldap,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password,
                    $auth)
        }
        else {
            $d = New-Object DirectoryServices.DirectoryEntry($ldap)
            $d.AuthenticationType = $auth
        }

        [void]$d.NativeObject
        $d
    }
    catch {
        # 呼び出し側がロケール非依存で no-such-object 等を判定できるよう HRESULT を付与する
        $hr = $null
        $ex = $_.Exception
        while ($ex) {
            if ($ex -is [System.Runtime.InteropServices.COMException]) { $hr = $ex.HResult; break }
            $ex = $ex.InnerException
        }
        $hrText = ''
        if ($null -ne $hr) { $hrText = ' (0x{0:X8})' -f ([uint32]($hr -band 0xffffffffL)) }
        throw "New-ADSConnection に失敗しました (Server='$Server', Path='$Path', UseSSL=$UseSSL)$($hrText): $($_.Exception.Message)"
    }
}

function ADSI_NewSearcher {
    param(
        [DirectoryServices.DirectoryEntry]$SearchRoot,
        $Filter,
        [ValidateSet('Base','OneLevel','Subtree')]$Scope = 'Subtree',
        [string[]]$Properties,
        [switch]$Tombstone,
        [int]$ClientTimeoutSec = 0   # 0 = 無制限。ハング防止のクライアント側タイムアウト
    )

    $s            = New-Object DirectoryServices.DirectorySearcher
    $s.SearchRoot = $SearchRoot
    $s.Filter     = $Filter
    $s.PageSize   = 1000   # ページング。サーバー負荷を平準化し大量結果でも安定取得
    $s.SizeLimit  = 0

    if ($ClientTimeoutSec -gt 0) {
        $s.ClientTimeout    = [TimeSpan]::FromSeconds($ClientTimeoutSec)
        $s.ServerTimeLimit  = [TimeSpan]::FromSeconds($ClientTimeoutSec)
    }

    switch ($Scope) {
        Base     { $s.SearchScope = [DirectoryServices.SearchScope]::Base     }
        OneLevel { $s.SearchScope = [DirectoryServices.SearchScope]::OneLevel }
        default  { $s.SearchScope = [DirectoryServices.SearchScope]::Subtree  }
    }

    if ($Tombstone) { $s.Tombstone = $true }

    if ($Properties -and ($Properties -notcontains '*')) {
        foreach ($p in ($Properties | Where-Object { $_ } | Select-Object -Unique)) {
            [void]$s.PropertiesToLoad.Add($p)
        }
    }

    $s
}

function ADSI_BuildRawObject($r) {
    $p = $r.Properties
    $o = [ordered]@{}
    foreach ($n in ($p.PropertyNames | Sort-Object)) {
        $v  = @($p[$n])
        $ln = ([string]$n).ToLowerInvariant()
        if ($ln -eq 'objectguid' -and $v.Count) {
            # RSAT と同型（Guid オブジェクト）で返す
            $o[$n] = New-Object Guid (,[byte[]]$v[0])
        }
        elseif ($ln -eq 'objectsid' -and $v.Count) {
            # RSAT と同型（SecurityIdentifier オブジェクト）で返す
            try   { $o[$n] = New-Object Security.Principal.SecurityIdentifier ([byte[]]$v[0]), 0 }
            catch { $o[$n] = $v[0] }
        }
        elseif ($v.Count -eq 1) { $o[$n] = $v[0]  }
        else                    { $o[$n] = ,@($v)  }
    }
    [pscustomobject]$o
}

function ADSI_BuildMappedObject($r, [string[]]$Props) {
    $p = $r.Properties
    $o = [ordered]@{}
    foreach ($n in $Props) {
        $d = $script:ADSI_OutputDefs[$n]
        if (!$d) {
            $o[$n] = ADSI_ReadConverted $p $n
            continue
        }
        $l = $d.Ldap
        switch ($d.Kind) {
            direct    { $o[$n] = ADSI_ReadConverted $p $l }
            guid      { $o[$n] = ADSI_ReadConverted $p $l guid }
            sid       { $o[$n] = ADSI_ReadConverted $p $l sid }
            lastvalue {
                $v     = if ($p.Contains($l.ToLowerInvariant())) { @($p[$l.ToLowerInvariant()]) } else { @() }
                $o[$n] = if ($v.Count) { $v[-1] } else { $null }
            }
            uac       { $o[$n] = ADSI_UacToEnabled(ADSI_FirstVal $p $l) }
            filetime  { $o[$n] = ADSI_FileTimeToDate(ADSI_FirstVal $p $l) }
            lockedout    { $o[$n] = ADSI_HasFlag (ADSI_FirstVal $p $l) 0x10 }      # LOCK_OUT
            pwdexpired   { $o[$n] = ADSI_HasFlag (ADSI_FirstVal $p $l) 0x800000 }  # PASSWORD_EXPIRED
            pwdneverexp  { $o[$n] = ADSI_HasFlag (ADSI_FirstVal $p $l) 0x10000 }   # DONT_EXPIRE_PASSWD
            pwdnotreq    { $o[$n] = ADSI_HasFlag (ADSI_FirstVal $p $l) 0x20 }      # PASSWD_NOTREQD
            smartcardreq { $o[$n] = ADSI_HasFlag (ADSI_FirstVal $p $l) 0x40000 }   # SMARTCARD_REQUIRED
            trusteddeleg { $o[$n] = ADSI_HasFlag (ADSI_FirstVal $p $l) 0x80000 }   # TRUSTED_FOR_DELEGATION
            agedays      { $o[$n] = ADSI_AgeInDays(ADSI_FirstVal $p $l) }
            scope     { $o[$n] = ADSI_GroupScope(ADSI_FirstVal $p $l) }
            cat       { $o[$n] = ADSI_GroupCategory(ADSI_FirstVal $p $l) }
            ipv4      { $o[$n] = ADSI_ResolveIPv4(ADSI_FirstVal $p $l) }
            ipv6      { $o[$n] = ADSI_ResolveIPv6(ADSI_FirstVal $p $l) }
            gplink    { $o[$n] = ADSI_ParseGpLink(ADSI_FirstVal $p $l) }
            default   { $o[$n] = ADSI_ReadConverted $p $l }
        }
    }
    [pscustomobject]$o
}

function ADSI_GetAttrs($Conn, $DN, [string[]]$Attrs) {
    $s = ADSI_NewSearcher -SearchRoot $Conn -Filter "(distinguishedName=$(ADSI_EscapeLdapValue $DN))" -Properties $Attrs
    try {
        $r = $s.FindOne()
        if ($r) { $r.Properties } else { $null }
    }
    finally { $s.Dispose() }
}

function ADSI_Query {
    param(
        $Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        $SearchBase,
        [ValidateSet('Base','OneLevel','Subtree')]$SearchScope = 'Subtree',
        [string[]]$Properties,
        $Filter,
        [string[]]$DefaultProps,
        [ValidateSet('Default','Config','Schema','ForestDns')]$NamingContext = 'Default',
        [switch]$Tombstone,
        [int]$ResultSetSize = 0,        # 0 = 無制限。>0 で件数上限。超過時は警告
        [int]$TimeoutSeconds = 0,       # 0 = 無制限。>0 でクライアント側タイムアウト
        [string]$ProgressActivity       # 指定時のみ Write-Progress で進捗表示
    )

    if (!$Filter) { $Filter = '(objectClass=*)' }

    $c = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $SearchBase -NamingContext $NamingContext
    try {
        $raw = @($Properties) -contains '*'
        if ($raw) {
            $load  = @()
            $props = @()
        }
        else {
            $props = @(@($DefaultProps) + @($Properties)) | Where-Object { $_ } | Select-Object -Unique
            $load  = @()
            foreach ($n in $props) {
                $d = $script:ADSI_OutputDefs[$n]
                if ($d) { $load += $d.Ldap } else { $load += $n }
            }
            $load = @($load) | Where-Object { $_ } | Select-Object -Unique
        }

        $s   = ADSI_NewSearcher -SearchRoot $c -Filter $Filter -Scope $SearchScope -Properties $load -Tombstone:$Tombstone -ClientTimeoutSec $TimeoutSeconds
        $res = $null
        $count = 0
        $sw    = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $res = $s.FindAll()
            foreach ($r in $res) {
                if ($ResultSetSize -gt 0 -and $count -ge $ResultSetSize) {
                    Write-Warning "結果が上限 $ResultSetSize 件に達したため打ち切りました（-ResultSetSize で変更可、0 で無制限）。"
                    break
                }
                if ($TimeoutSeconds -gt 0 -and $sw.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                    Write-Warning "処理時間が $TimeoutSeconds 秒を超えたため打ち切りました（-Timeout で変更可）。"
                    break
                }

                if ($raw) { ADSI_BuildRawObject $r }
                else      { ADSI_BuildMappedObject $r $props }

                $count++
                if ($ProgressActivity -and ($count % 250 -eq 0)) {
                    Write-Progress -Activity $ProgressActivity -Status "$count 件取得 ($([int]$sw.Elapsed.TotalSeconds) 秒)"
                }
            }
        }
        finally {
            if ($ProgressActivity) { Write-Progress -Activity $ProgressActivity -Completed }
            if ($res) { $res.Dispose() }
            $s.Dispose()
        }
    }
    finally { $c.Dispose() }
}

# ------------------------------------------------------------
# グループメンバー取得の補助（再帰展開・大規模グループ対応）
# ------------------------------------------------------------

<#
.SYNOPSIS
    グループの member 属性を range 取得で全件読み出す
.DESCRIPTION
    AD は member が約1500件を超えると1回の取得で打ち切る（range 制限）。
    member;range=0-* → 1500-* … と段階取得して取りこぼしを防ぐ。
    1回あたり1クエリのため負荷は低い。
.OUTPUTS
    メンバーDN文字列の配列
#>
function ADSI_GetMemberDNsRanged {
    param(
        [DirectoryServices.DirectoryEntry]$Conn,
        [string]$GroupDN,
        [int]$ClientTimeoutSec = 0
    )

    $result = New-Object System.Collections.Generic.List[string]
    $low    = 0
    $filter = "(distinguishedName=$(ADSI_EscapeLdapValue $GroupDN))"

    while ($true) {
        $attr = "member;range=$low-*"
        $s = ADSI_NewSearcher -SearchRoot $Conn -Filter $filter -Scope Subtree -Properties @($attr) -ClientTimeoutSec $ClientTimeoutSec
        $r = $null
        try { $r = $s.FindOne() } finally { $s.Dispose() }
        if (-not $r) { break }

        $p = $r.Properties
        $rangeName = $null
        foreach ($pn in $p.PropertyNames) {
            if (([string]$pn).ToLowerInvariant().StartsWith('member;range=')) { $rangeName = $pn; break }
        }

        if (-not $rangeName) {
            # range 属性が返らない = 小規模グループ（plain member）またはメンバーなし
            if ($p.Contains('member')) {
                foreach ($v in $p['member']) { $result.Add([string]$v) }
            }
            break
        }

        $vals = @($p[$rangeName])
        foreach ($v in $vals) { $result.Add([string]$v) }

        # 末尾が "-*" なら最終ブロック
        if (([string]$rangeName).EndsWith('-*')) { break }
        if ($vals.Count -eq 0) { break }
        $low += $vals.Count
    }

    return ,$result.ToArray()
}

<#
.SYNOPSIS
    DN のリストをまとめてオブジェクト解決する
.DESCRIPTION
    distinguishedName の OR フィルターでチャンク（既定50件）ごとに問い合わせ、
    クエリ回数を抑える。各オブジェクトの種別（グループか否か）も判定する。
.OUTPUTS
    DistinguishedName / Name / SamAccountName / ObjectClass / SID / IsGroup を持つオブジェクト
#>
function ADSI_ResolveDNObjects {
    param(
        [DirectoryServices.DirectoryEntry]$Conn,
        [string[]]$DNs,
        [int]$ClientTimeoutSec = 0
    )

    $out = New-Object System.Collections.Generic.List[object]
    if (-not $DNs -or $DNs.Count -eq 0) { return ,$out.ToArray() }

    $chunkSize = 50
    for ($i = 0; $i -lt $DNs.Count; $i += $chunkSize) {
        $end   = [Math]::Min($i + $chunkSize - 1, $DNs.Count - 1)
        $chunk = $DNs[$i..$end]
        $ors   = ($chunk | ForEach-Object { "(distinguishedName=$(ADSI_EscapeLdapValue $_))" }) -join ''
        $filter = "(|$ors)"

        $s = ADSI_NewSearcher -SearchRoot $Conn -Filter $filter -Scope Subtree `
                -Properties @('distinguishedName','name','sAMAccountName','objectClass','objectSid') `
                -ClientTimeoutSec $ClientTimeoutSec
        $res = $null
        try {
            $res = $s.FindAll()
            foreach ($r in $res) {
                $p  = $r.Properties
                $oc = @($p['objectclass'])
                $sid = $null
                if ($p.Contains('objectsid') -and $p['objectsid'].Count) {
                    # RSAT と同型（SecurityIdentifier オブジェクト）で返す
                    try { $sid = New-Object Security.Principal.SecurityIdentifier ([byte[]]$p['objectsid'][0]), 0 } catch {}
                }
                $out.Add([pscustomobject]@{
                    DistinguishedName = [string]$p['distinguishedname'][0]
                    Name              = if ($p.Contains('name'))           { [string]$p['name'][0] }           else { $null }
                    SamAccountName    = if ($p.Contains('samaccountname')) { [string]$p['samaccountname'][0] } else { $null }
                    ObjectClass       = if ($oc.Count)                     { [string]$oc[-1] }                 else { $null }
                    SID               = $sid
                    IsGroup           = ($oc -contains 'group')
                })
            }
        }
        finally {
            if ($res) { $res.Dispose() }
            $s.Dispose()
        }
    }

    return ,$out.ToArray()
}

# グループ SID の末尾 RID を取り、(primaryGroupID=<RID>) でプライマリメンバーを検索する。
# Domain Users / Domain Computers 等は member 属性が空のため、この経路でしか取得できない。
# -MaxResults 指定時は primaryGroupID 検索を上限件数で打ち切る（大規模グループのメモリ保護）。
function ADSI_GetPrimaryGroupMembers {
    param(
        [DirectoryServices.DirectoryEntry]$Conn,
        $GroupSid,            # SecurityIdentifier または SID 文字列
        [int]$ClientTimeoutSec = 0,
        [int]$MaxResults = 0
    )

    $out = New-Object System.Collections.Generic.List[object]

    if ($null -eq $GroupSid -or [string]::IsNullOrWhiteSpace([string]$GroupSid)) {
        return ,$out.ToArray()
    }

    $sidStr = [string]$GroupSid
    $parts  = $sidStr -split '-'
    $rid    = $parts[-1]
    if ([string]::IsNullOrWhiteSpace($rid)) { return ,$out.ToArray() }

    $filter = "(primaryGroupID=$rid)"
    $s = ADSI_NewSearcher -SearchRoot $Conn -Filter $filter -Scope Subtree `
            -Properties @('distinguishedName','name','sAMAccountName','objectClass','objectSid') `
            -ClientTimeoutSec $ClientTimeoutSec
    $res = $null
    try {
        $res = $s.FindAll()
        foreach ($r in $res) {
            $p  = $r.Properties
            $oc = @($p['objectclass'])
            $sid = $null
            if ($p.Contains('objectsid') -and $p['objectsid'].Count) {
                # RSAT と同型（SecurityIdentifier オブジェクト）で返す
                try { $sid = New-Object Security.Principal.SecurityIdentifier ([byte[]]$p['objectsid'][0]), 0 } catch {}
            }
            $out.Add([pscustomobject]@{
                DistinguishedName = [string]$p['distinguishedname'][0]
                Name              = if ($p.Contains('name'))           { [string]$p['name'][0] }           else { $null }
                SamAccountName    = if ($p.Contains('samaccountname')) { [string]$p['samaccountname'][0] } else { $null }
                ObjectClass       = if ($oc.Count)                     { [string]$oc[-1] }                 else { $null }
                SID               = $sid
                IsGroup           = ($oc -contains 'group')
            })
            if ($MaxResults -gt 0 -and $out.Count -ge $MaxResults) { break }
        }
    }
    finally {
        if ($res) { $res.Dispose() }
        $s.Dispose()
    }

    return ,$out.ToArray()
}

function ADSI_ThrowLdap($ErrorRecord, $Context) {
    $p = @()
    if ($Context) { $p += $Context }
    $e = $ErrorRecord.Exception
    while ($e) {
        $p += $e.Message
        $e  = $e.InnerException
    }
    throw ($p -join ' | ')
}

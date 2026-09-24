# ============================================================
# ADSearch.Diagnostics.ps1
# ユーザー視点のアカウント健全性サマリーを返す診断コマンド。
# オンプレ AD にスタンプされた属性のみ対象。Exchange Online 側の情報は対象外。
# すべて読み取り専用。
# ============================================================

<#
.SYNOPSIS
    AD ユーザーのアカウント・メール・グループ所属を1オブジェクトで返す

.DESCRIPTION
    ログイントラブル・メール設定・グループ所属を一括確認するための診断サマリー。
    内部で Get-ADUser を1回呼び出し、Exchange 属性もあわせて取得する。

    取得できるのはオンプレ AD にスタンプされた値のみ。
    以下は AD に存在しないため対象外:
      - Exchange Online 側でしか分からない情報
        （実メールボックスサイズ・EXO 側のブロック状態・EXO 検疫状態 等）

    WhenCreated/WhenChanged はアカウント作成時期・最終変更の切り分け用。
    -Recursive を指定すると LDAP_MATCHING_RULE_IN_CHAIN（OID: 1.2.840.113556.1.4.1941）
    による単一クエリでネスト展開済みグループ一覧を返す。

    -Identity は sAMAccountName/DN/GUID/SID に加え、UPN・メールアドレス（@ を含む値）も受理する。

.EXAMPLE
    Get-ADUserHealth -Identity yamada -Server dc01.corp.local
    # アカウント状態・メール属性・直接所属グループを一括確認

.EXAMPLE
    Get-ADUserHealth -Identity yamada@contoso.com -Server dc01.corp.local -Recursive
    # ネスト展開したグループ一覧を含めて返す

.EXAMPLE
    Get-ADUserHealth -Identity yamada -Server dc01.corp.local | Format-List
    # 全プロパティを縦に表示
#>
function Get-ADUserHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)][string]$Identity,
        # グループ所属を再帰展開（既定は直接所属のみ）
        [switch]$Recursive,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$Timeout = 0
    )

    try {
        # ---- 1. ユーザー取得（1回のクエリで全属性を要求） ----
        # フレンドリー名（$script:ADSI_OutputDefs 登録済み）と生 LDAP 属性を混在して指定する。
        # Get-ADUser は未登録の名前はそのまま LDAP 属性名として DirectorySearcher に渡す。
        $props = @(
            # アカウント状態系（登録済みフレンドリー名）
            'Enabled','LockedOut','PasswordExpired','PasswordExpiryDate','PasswordNeverExpires',
            'AccountExpirationDate','PasswordLastSet','LastLogonDate',
            'BadLogonCount','AccountLockoutTime',
            'Created','Modified',
            # 識別子系
            'DisplayName','UserPrincipalName','SamAccountName','DistinguishedName','Description',
            # グループ所属（直接）
            'MemberOf',
            # Exchange / メール属性（生 LDAP 属性名として渡す）
            'mailNickname','proxyAddresses','targetAddress',
            'msExchRemoteRecipientType','msExchRecipientTypeDetails','msExchHideFromAddressLists'
        )

        $e = ADSI_EscapeLdapValue $Identity
        $useUpnLookup = ($Identity -match '@') -and
                        ($Identity -notmatch '^(?i)(CN|OU|DC)=') -and
                        ($Identity -notmatch '^S-1-')
        if ($useUpnLookup) {
            $user = Get-ADUser -LDAPFilter "(|(userPrincipalName=$e)(mail=$e))" `
                        -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                        -SearchBase $SearchBase -Properties $props -Timeout $Timeout |
                    Select-Object -First 1
        }
        else {
            $user = Get-ADUser -Identity $Identity -Server $Server -UseSSL:$UseSSL `
                        -Credential $Credential -SearchBase $SearchBase `
                        -Properties $props -Timeout $Timeout |
                    Select-Object -First 1
        }

        if (-not $user) {
            throw "ユーザーが見つかりません: $Identity"
        }

        # ---- 2. メールセクション ----
        # proxyAddresses は登録済みフレンドリー名 ProxyAddresses 経由でも取れるが、
        # Exchange ヘルパーは生の多値配列を期待するのでキャストして渡す。
        $proxies = if ($null -ne $user.proxyAddresses) { @($user.proxyAddresses) } else { @() }

        $primarySmtp         = ADSI_PrimarySmtp $proxies
        $emailAddresses      = ADSI_SmtpAddresses $proxies

        # targetAddress の smtp: プレフィックスを除去（EMS の RemoteRoutingAddress と同形式）
        $remoteRoutingAddress = ADSI_StripSmtpPrefix $user.targetAddress

        $remoteRecipientType  = ADSI_DecodeRemoteRecipientType $user.msExchRemoteRecipientType
        $recipientTypeDetails = ADSI_DecodeRecipientTypeDetails $user.msExchRecipientTypeDetails
        $hiddenFromAL         = ADSI_HideFromAL $user.msExchHideFromAddressLists
        $mailEnabled          = [bool]($user.mailNickname)

        # ---- 3. グループ所属 ----
        $groups = $null

        if ($Recursive) {
            # LDAP_MATCHING_RULE_IN_CHAIN（OID: 1.2.840.113556.1.4.1941）で
            # ネスト展開済みの全所属グループを単一クエリで取得する。
            # 直接・間接を問わずユーザーが推移的メンバーになっている全グループが返る。
            $nc   = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
            $base = if ($SearchBase) { $SearchBase } else { $nc.Default }

            $escapedDN = ADSI_EscapeLdapValue ([string]$user.DistinguishedName)
            $chainFilter = "(member:1.2.840.113556.1.4.1941:=$escapedDN)"

            $conn = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $base
            try {
                $s = ADSI_NewSearcher -SearchRoot $conn -Filter $chainFilter -Scope Subtree -Properties @('name')
                if ($Timeout -gt 0) {
                    $s.ClientTimeout = [timespan]::FromSeconds($Timeout)
                    $s.ServerTimeLimit = [timespan]::FromSeconds($Timeout)
                }
                $res = $null
                try {
                    $res = $s.FindAll()
                    $groupList = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($r in $res) {
                        $n = $r.Properties['name']
                        if ($n -and $n.Count -gt 0) {
                            $groupList.Add([string]$n[0])
                        }
                    }
                    $groups = @($groupList | Sort-Object -Unique)
                }
                finally {
                    if ($res) { $res.Dispose() }
                    $s.Dispose()
                }
            }
            finally {
                $conn.Dispose()
            }
        }
        else {
            # 直接所属のみ: memberOf の各 DN から葉 CN を抽出
            $memberOf = $user.MemberOf
            if ($null -ne $memberOf) {
                $groups = @(@($memberOf) | ForEach-Object { ADSI_LeafCn ([string]$_) } | Sort-Object -Unique)
            }
            else {
                $groups = @()
            }
        }

        if ($null -eq $groups) { $groups = @() }

        # ---- 4. 出力オブジェクト（論理グループ順） ----
        [pscustomobject]@{
            # 識別子・アカウント状態
            Name                  = if ($user.DisplayName) { [string]$user.DisplayName } else { [string]$user.SamAccountName }
            SamAccountName        = [string]$user.SamAccountName
            UserPrincipalName     = [string]$user.UserPrincipalName
            DisplayName           = [string]$user.DisplayName
            Description           = [string]$user.Description
            Enabled               = $user.Enabled
            LockedOut             = $user.LockedOut
            PasswordExpired       = $user.PasswordExpired
            PasswordExpiryDate    = $user.PasswordExpiryDate
            PasswordNeverExpires  = $user.PasswordNeverExpires
            AccountExpirationDate = $user.AccountExpirationDate
            PasswordLastSet       = $user.PasswordLastSet
            LastLogonDate         = $user.LastLogonDate
            BadLogonCount         = $user.BadLogonCount
            AccountLockoutTime    = $user.AccountLockoutTime
            # whenCreated / whenChanged の切り分け用
            WhenCreated           = $user.Created
            WhenChanged           = $user.Modified
            # メール
            MailEnabled           = $mailEnabled
            PrimarySmtpAddress    = $primarySmtp
            EmailAddresses        = $emailAddresses
            RemoteRoutingAddress  = $remoteRoutingAddress
            RemoteRecipientType   = $remoteRecipientType
            RecipientTypeDetails  = $recipientTypeDetails
            HiddenFromAddressLists = $hiddenFromAL
            # グループ所属
            GroupCount            = $groups.Count
            Groups                = $groups
            # 識別子（末尾）
            DistinguishedName     = [string]$user.DistinguishedName
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADUserHealth に失敗しました' }
}

<#
.SYNOPSIS
    非アクティブ・無効・期限切れ・ロック等のアカウントを検索する（RSAT Search-ADAccount 互換のサブセット）

.DESCRIPTION
    RSAT の Search-ADAccount と同様のパラメーターセット（AccountInactive/AccountDisabled/AccountExpired/
    PasswordExpired/PasswordNeverExpires/LockedOut）でアカウントを棚卸しする。
    既定ではユーザー・コンピューターの両方を対象とする（-UsersOnly / -ComputersOnly で絞り込み）。

    注意:
      - `-AccountInactive` は lastLogonTimestamp を判定に使うため、
        レプリケーション遅延（既定で最大約14日）により結果に最大14日程度の誤差を含む（RSAT も同じ制約）。
      - `-PasswordExpired` / `-LockedOut` は構築属性（DC 計算値）のためサーバー側フィルターができず、
        取得後にクライアント側で絞り込む。大規模環境では -SearchBase で対象を絞ることを推奨。

.EXAMPLE
    # 90日以上ログオンのないユーザー
    Search-ADAccount -AccountInactive -DaysInactive 90 -UsersOnly -Server dc01

.EXAMPLE
    # ロックアウト中のユーザー
    Search-ADAccount -LockedOut -Server dc01
#>
function Search-ADAccount {
    [CmdletBinding(DefaultParameterSetName = 'AccountInactive')]
    param(
        [Parameter(ParameterSetName = 'AccountInactive')] [switch]$AccountInactive,
        [Parameter(ParameterSetName = 'AccountInactive')] [timespan]$TimeSpan,
        [Parameter(ParameterSetName = 'AccountInactive')] [int]$DaysInactive = 0,
        [Parameter(ParameterSetName = 'AccountDisabled', Mandatory = $true)] [switch]$AccountDisabled,
        [Parameter(ParameterSetName = 'AccountExpired',  Mandatory = $true)] [switch]$AccountExpired,
        [Parameter(ParameterSetName = 'PasswordExpired', Mandatory = $true)] [switch]$PasswordExpired,
        [Parameter(ParameterSetName = 'PasswordNeverExpires', Mandatory = $true)] [switch]$PasswordNeverExpires,
        [Parameter(ParameterSetName = 'LockedOut',       Mandatory = $true)] [switch]$LockedOut,
        [switch]$UsersOnly,
        [switch]$ComputersOnly,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )

    try {
        if ($UsersOnly -and $ComputersOnly) {
            throw '-UsersOnly と -ComputersOnly は同時に指定できません'
        }

        # ---- 対象オブジェクトフィルター ----
        $objectFilter =
            if ($UsersOnly)          { '(&(objectCategory=person)(objectClass=user))' }
            elseif ($ComputersOnly)  { '(objectCategory=computer)' }
            else                     { '(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))' }

        $defaultProps = @(
            'DistinguishedName','Name','SamAccountName','ObjectClass','SID','Enabled','LockedOut',
            'PasswordExpired','PasswordNeverExpires','AccountExpirationDate','LastLogonDate','PasswordLastSet'
        )

        # クライアント側判定が必要かどうか（5. PasswordExpired / 6. LockedOut）
        $clientSideFilterKind = $null

        switch ($PSCmdlet.ParameterSetName) {
            'AccountInactive' {
                if (-not $PSBoundParameters.ContainsKey('TimeSpan') -and $DaysInactive -le 0) {
                    throw '-TimeSpan または -DaysInactive で期間を指定してください'
                }
                $span = if ($PSBoundParameters.ContainsKey('TimeSpan')) { $TimeSpan } else { [timespan]::FromDays($DaysInactive) }
                $ft   = (Get-Date).Subtract($span).ToFileTime()
                $condFilter = "(|(lastLogonTimestamp<=$ft)(!(lastLogonTimestamp=*)))"
            }
            'AccountDisabled' {
                $condFilter = '(userAccountControl:1.2.840.113556.1.4.803:=2)'
            }
            'AccountExpired' {
                $now = (Get-Date).ToFileTime()
                $condFilter = "(&(accountExpires<=$now)(!(accountExpires=0))(!(accountExpires=9223372036854775807)))"
            }
            'PasswordNeverExpires' {
                $condFilter = '(userAccountControl:1.2.840.113556.1.4.803:=65536)'
            }
            'PasswordExpired' {
                # 構築属性のためサーバー側フィルター不可。無効アカウントのみサーバー側で除外し、残りはクライアント側判定。
                $condFilter = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
                $clientSideFilterKind = 'PasswordExpired'
            }
            'LockedOut' {
                # ロック期間経過を正確に判定するため候補のみサーバー側で絞り、クライアント側で確定判定する。
                $condFilter = '(lockoutTime>=1)'
                $clientSideFilterKind = 'LockedOut'
            }
        }

        $filter = ADSI_AndFilters $objectFilter $condFilter

        $queryParams = @{
            Server           = $Server
            UseSSL           = $UseSSL
            Credential       = $Credential
            SearchBase       = $SearchBase
            Filter           = $filter
            DefaultProps     = $defaultProps
            TimeoutSeconds   = $Timeout
            ProgressActivity = 'Search-ADAccount'
        }

        if ($clientSideFilterKind) {
            # クライアント側判定の場合は ADSI_Query に ResultSetSize を渡さず、絞り込み後に上限を適用する。
            $results = ADSI_Query @queryParams

            $filtered =
                switch ($clientSideFilterKind) {
                    'PasswordExpired' { @($results | Where-Object { $_.PasswordExpired -eq $true }) }
                    'LockedOut'       { @($results | Where-Object { $_.LockedOut -eq $true }) }
                }

            if ($ResultSetSize -gt 0 -and $filtered.Count -gt $ResultSetSize) {
                Write-Warning "結果が上限 $ResultSetSize 件に達したため打ち切りました（-ResultSetSize で変更可、0 で無制限）。"
                $filtered = $filtered[0..($ResultSetSize - 1)]
            }

            $filtered
        }
        else {
            $queryParams.ResultSetSize = $ResultSetSize
            ADSI_Query @queryParams
        }
    }
    catch { ADSI_ThrowLdap $_ 'Search-ADAccount に失敗しました' }
}

<#
.SYNOPSIS
    AD コンピュータの信頼関係（セキュアチャネル）健全性を1オブジェクトで返す

.DESCRIPTION
    Get-ADUserHealth のコンピュータ版。コンピュータアカウントのセキュアチャネル
    トラブルの一次切り分けを1オブジェクトで確認するための診断サマリー。
    内部で Get-ADComputer を1回呼び出す。

    -Identity にはコンピュータ名を sAMAccountName 形式（末尾 `$` の有無どちらでも可）で指定できる。
    末尾に `$` が無い場合、まず与えられた値でそのまま検索し、見つからなければ
    末尾に `$` を付けて再試行する（sAMAccountName は内部的に `PC001$` 形式のため）。

    MachinePasswordStale が $true の場合、そのPCが長期間オフラインだったか、
    セキュアチャネル（信頼関係）が壊れている可能性がある。PC側での
    Test-ComputerSecureChannel 実行を推奨。

.EXAMPLE
    Get-ADComputerHealth -Identity PC001 -Server dc01.corp.local
    # コンピュータ名（$ 無し）で健全性を確認

.EXAMPLE
    Get-ADComputerHealth -Identity 'PC001$' -Server dc01.corp.local | Format-List
    # sAMAccountName 形式（$ 付き）で指定し全プロパティを縦に表示
#>
function Get-ADComputerHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)][string]$Identity,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$Timeout = 0
    )

    try {
        # ---- 1. コンピュータ取得（1回のクエリで全属性を要求） ----
        $props = @(
            'Enabled','LastLogonDate','PasswordLastSet','MachinePasswordAge',
            'OperatingSystem','OperatingSystemVersion','OperatingSystemServicePack',
            'DNSHostName','IPv4Address','IPv6Address','Description','Created','Modified',
            'MemberOf','Location','ManagedBy','ServicePrincipalName'
        )

        $getParams = @{
            Server     = $Server
            UseSSL     = $UseSSL
            Credential = $Credential
            SearchBase = $SearchBase
            Properties = $props
            Timeout    = $Timeout
        }

        $computer = $null
        try {
            $computer = Get-ADComputer -Identity $Identity @getParams | Select-Object -First 1
        }
        catch {
            # 「見つからない」場合のみ $ 付き sAMAccountName で再試行する。
            # 認証/接続エラー等はそのまま送出して真因を隠さない。
            $msg = $_.Exception.Message
            $notFound = ($msg -match '見つかりません') -or (ADSI_IsNoSuchObject $msg)
            if ($notFound -and -not $Identity.EndsWith('$')) {
                $computer = Get-ADComputer -Identity "$Identity`$" @getParams | Select-Object -First 1
            }
            else {
                throw
            }
        }

        if (-not $computer) {
            throw "コンピュータが見つかりません: $Identity"
        }

        # ---- 2. グループ所属 ----
        # 直接所属のみ: memberOf の各 DN から葉 CN を抽出（Get-ADUserHealth の非再帰パスと同実装）
        $memberOf = $computer.MemberOf
        $groups =
            if ($null -ne $memberOf) {
                @(@($memberOf) | ForEach-Object { ADSI_LeafCn ([string]$_) } | Sort-Object -Unique)
            }
            else {
                @()
            }

        # ---- 3. マシンパスワード鮮度判定 ----
        # 既定のマシンパスワード更新周期は30日。超過は長期オフラインまたは信頼関係失敗の疑い
        $machinePasswordStale =
            if ($null -eq $computer.MachinePasswordAge) { $null }
            else { $computer.MachinePasswordAge -gt 30 }

        # ---- 4. SPN 件数 ----
        $spnCount = if ($null -ne $computer.ServicePrincipalName) { @($computer.ServicePrincipalName).Count } else { 0 }

        # ---- 5. DNS 登録状況 ----
        $dnsRegistered = ($null -ne $computer.IPv4Address) -or ($null -ne $computer.IPv6Address)

        # ---- 6. 識別子（末尾 $ を除いた Name） ----
        $samAccountName = [string]$computer.SamAccountName
        $name = if ($samAccountName.EndsWith('$')) { $samAccountName.Substring(0, $samAccountName.Length - 1) } else { $samAccountName }

        # ---- 7. 出力オブジェクト（論理グループ順） ----
        [pscustomobject]@{
            # 識別子
            Name                  = $name
            SamAccountName        = $samAccountName
            DNSHostName           = [string]$computer.DNSHostName
            Description           = [string]$computer.Description
            # アカウント状態
            Enabled               = $computer.Enabled
            LastLogonDate         = $computer.LastLogonDate
            # セキュアチャネル
            PasswordLastSet       = $computer.PasswordLastSet
            MachinePasswordAge    = $computer.MachinePasswordAge
            MachinePasswordStale  = $machinePasswordStale
            # OS
            OperatingSystem            = [string]$computer.OperatingSystem
            OperatingSystemVersion     = [string]$computer.OperatingSystemVersion
            OperatingSystemServicePack = [string]$computer.OperatingSystemServicePack
            # ネットワーク
            IPv4Address           = $computer.IPv4Address
            IPv6Address           = $computer.IPv6Address
            DnsRegistered         = $dnsRegistered
            # 管理情報
            Location              = [string]$computer.Location
            ManagedBy             = [string]$computer.ManagedBy
            SPNCount              = $spnCount
            # グループ所属
            GroupCount            = $groups.Count
            Groups                = $groups
            # 時刻
            WhenCreated           = $computer.Created
            WhenChanged           = $computer.Modified
            # 識別子（末尾）
            DistinguishedName     = [string]$computer.DistinguishedName
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADComputerHealth に失敗しました' }
}

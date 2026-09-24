# ============================================================
# ADSearch.ExchangeRecipients.ps1
# Exchange 受信者（Recipient）情報を AD ドメイン NC から読み取る。
#
# Exchange がスタンプした AD 属性を読むため、Exchange Management Shell
# 相当の受信者コマンドを RSAT・Exchange サーバー接続なしで実行できる。
# 取得できるのは AD に格納された属性のみ。メールボックスサイズ・キュー・
# サービス稼働状態などの動的情報は AD に存在せず取得不可。
#
# Exchange 未導入 or 受信者なしの環境では空を返す（警告なし）。
# すべて読み取り専用。
# ============================================================

# ============================================================
# 受信者種別によらず必ず引く属性（2026-08-23 に8箇所から畳んだ）
#
# メールボックス／メールユーザー／リモート／連絡先／グループ／動的配布グループ／
# メンバー解決の**8箇所すべてに、この6つが複写されていた**。種別ごとに足す属性が
# 違うのは正しい（objectClass が別なので引ける属性も違う）が、共通部分まで
# 写していると、**新しく共通属性を1つ足したいときに8箇所を直すことになる。**
#
# 順序は出力に影響しない。`ADSI_NewSearcher` が `PropertiesToLoad.Add()` で
# 1つずつ足すだけで、返るオブジェクトの形は別のところで決まる。
# ============================================================

$script:ADSI_RecipientCoreAttrs = @(
    'name','displayName','mailNickname','mail','proxyAddresses','distinguishedName'
)

# ============================================================
# 内部ヘルパー（ADSI_ プレフィックス、モジュール外非公開）
# ============================================================

# proxyAddresses から Primary SMTP アドレスを返す（大文字 "SMTP:" のみ）
# 大文字・小文字を区別して先頭が "SMTP:" のエントリを探す。
# 複数一致の場合は最初の一致を返す。
function ADSI_PrimarySmtp($proxyAddresses) {
    foreach ($a in @($proxyAddresses)) {
        if ([string]$a -cmatch '^SMTP:(.+)$') {
            return $matches[1]
        }
    }
    return $null
}

# proxyAddresses を配列のまま返す（EmailAddresses プロパティ用）
function ADSI_SmtpAddresses($proxyAddresses) {
    if ($null -eq $proxyAddresses) { return @() }
    return @($proxyAddresses | Where-Object { $_ })
}

# Primary SMTP を解決。proxyAddresses に大文字 SMTP: が無ければ mail 属性にフォールバック。
function ADSI_ResolvePrimary($proxyAddresses, $mailFallback) {
    $primary = ADSI_PrimarySmtp $proxyAddresses
    if (-not $primary -and $mailFallback) { $primary = [string]$mailFallback }
    return $primary
}

# 'smtp:'/'SMTP:' プレフィックスを除いたアドレスを返す（EMS の RoutingAddress 形式）。空は $null。
function ADSI_StripSmtpPrefix($addr) {
    $s = [string]$addr
    if (-not $s) { return $null }
    return ($s -replace '^(?i)smtp:', '')
}

# msExchRecipientTypeDetails の数値を名称文字列に変換する。
# この属性は実運用上は単一値（マスクではなく識別子）として扱われる。
# 数値マッピングは Exchange チームが公開している既知の値に基づく。
# Microsoft Learn に一覧表は掲載されていないため、ベストエフォートとして扱う。
function ADSI_DecodeRecipientTypeDetails($v) {
    $n = ADSI_ToInt64 $v
    if ($null -eq $n) { return $null }
    # switch の case ラベルは int32 範囲のみ信頼できるため if/elseif で実装
    if      ($n -eq 1L)            { 'UserMailbox' }
    elseif  ($n -eq 2L)            { 'LinkedMailbox' }
    elseif  ($n -eq 4L)            { 'SharedMailbox' }
    elseif  ($n -eq 8L)            { 'LegacyMailbox' }
    elseif  ($n -eq 16L)           { 'RoomMailbox' }
    elseif  ($n -eq 32L)           { 'EquipmentMailbox' }
    elseif  ($n -eq 64L)           { 'MailContact' }
    elseif  ($n -eq 128L)          { 'MailUser' }
    elseif  ($n -eq 256L)          { 'MailUniversalDistributionGroup' }
    elseif  ($n -eq 512L)          { 'MailNonUniversalGroup' }
    elseif  ($n -eq 1024L)         { 'MailUniversalSecurityGroup' }
    elseif  ($n -eq 2048L)         { 'DynamicDistributionGroup' }
    elseif  ($n -eq 4096L)         { 'PublicFolder' }
    elseif  ($n -eq 8192L)         { 'SystemAttendantMailbox' }
    elseif  ($n -eq 16384L)        { 'SystemMailbox' }
    elseif  ($n -eq 32768L)        { 'MailForestContact' }
    elseif  ($n -eq 65536L)        { 'User' }
    elseif  ($n -eq 131072L)       { 'Contact' }
    elseif  ($n -eq 262144L)       { 'UniversalDistributionGroup' }
    elseif  ($n -eq 524288L)       { 'UniversalSecurityGroup' }
    elseif  ($n -eq 1048576L)      { 'NonUniversalGroup' }
    elseif  ($n -eq 2097152L)      { 'DisabledUser' }
    elseif  ($n -eq 4194304L)      { 'MicrosoftExchange' }
    elseif  ($n -eq 8388608L)      { 'ArbitrationMailbox' }
    elseif  ($n -eq 16777216L)     { 'MailboxPlan' }
    elseif  ($n -eq 33554432L)     { 'LinkedUser' }
    elseif  ($n -eq 268435456L)    { 'RoomList' }
    elseif  ($n -eq 536870912L)    { 'DiscoveryMailbox' }
    elseif  ($n -eq 1073741824L)   { 'RoleGroup' }
    elseif  ($n -eq 2147483648L)   { 'RemoteUserMailbox' }
    elseif  ($n -eq 8589934592L)   { 'RemoteRoomMailbox' }
    elseif  ($n -eq 17179869184L)  { 'RemoteEquipmentMailbox' }
    elseif  ($n -eq 34359738368L)  { 'RemoteSharedMailbox' }
    elseif  ($n -eq 137438953472L) { 'TeamMailbox' }
    else                           { "Unknown($n)" }
}

# msExchRemoteRecipientType はビットマスク。
# 各ビットの意味: 1=ProvisionMailbox, 2=ProvisionArchive, 4=Migrated,
#   8=DeprovisionMailbox, 16=DeprovisionArchive, 32=RoomMailbox,
#   64=EquipmentMailbox, 96(=32+64)=SharedMailbox
# EMS の表示スタイルに合わせてカンマ区切りで組み合わせを返す。
# 値 0 の場合は "None" を返す。
function ADSI_DecodeRemoteRecipientType($v) {
    $n = ADSI_ToInt64 $v
    if ($null -eq $n) { return $null }
    if ($n -eq 0) { return 'None' }

    $flags = New-Object System.Collections.Generic.List[string]

    # SharedMailbox は RoomMailbox(32) + EquipmentMailbox(64) の組み合わせ (96)
    # EMS は "ProvisionMailbox, SharedMailbox" のように表示する
    if (($n -band 96) -eq 96) {
        $flags.Add('SharedMailbox')
        # 残りビット（96 を除いた部分）を続けて評価
        $rest = $n -band (-bnot 96)
        if ($rest -band 1)  { $flags.Add('ProvisionMailbox')   }
        if ($rest -band 2)  { $flags.Add('ProvisionArchive')   }
        if ($rest -band 4)  { $flags.Add('Migrated')            }
        if ($rest -band 8)  { $flags.Add('DeprovisionMailbox')  }
        if ($rest -band 16) { $flags.Add('DeprovisionArchive')  }
    }
    else {
        if ($n -band 1)  { $flags.Add('ProvisionMailbox')   }
        if ($n -band 2)  { $flags.Add('ProvisionArchive')   }
        if ($n -band 4)  { $flags.Add('Migrated')            }
        if ($n -band 8)  { $flags.Add('DeprovisionMailbox')  }
        if ($n -band 16) { $flags.Add('DeprovisionArchive')  }
        if ($n -band 32) { $flags.Add('RoomMailbox')         }
        if ($n -band 64) { $flags.Add('EquipmentMailbox')    }
    }

    if ($flags.Count -eq 0) { return "Unknown($n)" }
    return ($flags -join ', ')
}

# msExchHideFromAddressLists → [bool]。属性が TRUE の場合のみ $true。
# 属性なし・NULL は $false（非表示でない）として扱う。
function ADSI_HideFromAL($v) {
    if ($null -eq $v) { return $false }
    $s = [string]$v
    return ($s -eq 'TRUE' -or $s -eq 'true' -or $s -eq '1')
}

# DN の先頭 RDN を除いた親 DN 文字列を返す。
# EMS の OrganizationalUnit は "domain.fqdn/OU/サブOU" 形式だが、
# 完全変換は複雑なため親 DN 文字列（例: "OU=Users,DC=corp,DC=local"）を返す。
# EMS と表示形式が異なる点は呼び出し元コメントで明記する。
function ADSI_OuFromDn([string]$dn) {
    if ([string]::IsNullOrWhiteSpace($dn)) { return $null }
    $idx = $dn.IndexOf(',')
    if ($idx -lt 0) { return $dn }
    return $dn.Substring($idx + 1)
}

# Identity に受信者固有の属性（mail, mailNickname, proxyAddresses）を追加して
# LDAP フィルターを生成する。
# ADSI_ResolveIdentityFilter は既存動作を変更しない。本関数はラッパー。
# SMTP アドレス形式（@ を含む）の場合は proxyAddresses も検索対象に加える。
function ADSI_ResolveRecipientIdentityFilter([string]$Identity) {
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }

    $id = $Identity.Trim()

    # DN / GUID / SID は既存ロジックに委譲
    if ($id -match '^(?i)(CN|OU|DC)=') {
        return "(distinguishedName=$(ADSI_EscapeLdapValue $id))"
    }

    $g = [guid]::Empty
    if ([guid]::TryParse($id, [ref]$g)) {
        return "(objectGUID=$(ADSI_GuidToLdapFilter $g))"
    }

    if ($id -match '^S-1-') {
        try { return "(objectSid=$(ADSI_SidToLdapFilter $id))" } catch {}
    }

    $e = ADSI_EscapeLdapValue $id

    if ($id -match '@') {
        # UPN / mail / proxyAddresses (LDAP は大文字小文字不問) で検索
        return "(|(userPrincipalName=$e)(mail=$e)(proxyAddresses=smtp:$e))"
    }

    # SAM / cn / name / mailNickname (alias) で検索
    return "(|(sAMAccountName=$e)(cn=$e)(name=$e)(mailNickname=$e))"
}

# 受信者向け LDAP フィルターを組み立てる。
# Identity 指定時は受信者固有属性（alias, proxyAddresses）も検索する。
# Filter / LDAPFilter は ADSI_BuildFinalFilter と同等の処理。
function ADSI_BuildRecipientFilter {
    param(
        [string]$ObjectFilter,
        [string]$Identity,
        [string]$LDAPFilter,
        [string]$Filter
    )

    if ($Identity) {
        $idFilter = ADSI_ResolveRecipientIdentityFilter $Identity
        return ADSI_AndFilters $ObjectFilter $idFilter
    }

    if ($LDAPFilter) {
        return ADSI_AndFilters $ObjectFilter $LDAPFilter
    }

    if ($Filter) {
        return ADSI_ConvertFilterToLDAP $Filter $ObjectFilter
    }

    return $ObjectFilter
}

# Exchange 受信者コマンド共通のドメイン NC クエリ実行
# Exchange 未導入環境（mailNickname オブジェクトなし）では空を返す。
function ADSI_RecipientRun {
    param(
        $Server, [switch]$UseSSL, [pscredential]$Credential,
        [string]$Filter,
        [string[]]$LoadAttrs,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0,
        [string]$SearchBase,
        [string]$ProgressActivity
    )
    try {
        ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase $SearchBase -SearchScope Subtree -NamingContext Default `
            -Filter $Filter -DefaultProps @() -Properties $LoadAttrs `
            -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity $ProgressActivity
    }
    catch {
        ADSI_ThrowLdap $_ $ProgressActivity
    }
}

# msExchMailboxGuid バイト配列を [guid] に変換して文字列を返す
function ADSI_BytesToGuid($bytes) {
    if ($null -eq $bytes) { return $null }
    try { (New-Object Guid (,[byte[]]@($bytes))).ToString() } catch { $null }
}

# msDS-ConsistencyGuid を Entra Connect の ImmutableId（Base64 文字列）に変換する。
# Entra Connect の既定ソースアンカーは msDS-ConsistencyGuid の Base64 表現。
function ADSI_ImmutableId($bytes) {
    if ($null -eq $bytes) { return $null }
    try { [Convert]::ToBase64String([byte[]]@($bytes)) } catch { $null }
}

# msExchPoliciesExcluded → EmailAddressPolicyEnabled 相当の [bool]。
# 全ポリシー除外のセンチネル GUID {26491cfc-9e50-4857-861b-0cb8df22b5d7} が
# 含まれていれば $false（ポリシー非適用）。
function ADSI_EapEnabled($values) {
    foreach ($v in @($values)) {
        if ([string]$v -match '(?i)26491cfc-9e50-4857-861b-0cb8df22b5d7') { return $false }
    }
    return $true
}

# ============================================================
# Get-Recipient
# ============================================================

<#
.SYNOPSIS
    Exchange 受信者オブジェクトの一覧を取得する（ドメイン NC）
.DESCRIPTION
    AD に mailNickname が設定されたオブジェクトを Exchange 受信者として返す。
    Exchange Management Shell の Get-Recipient 相当の構成スナップショット。
    属性は AD にスタンプされた値を読み取る（EMS と属性名が異なる場合がある）。
    動的情報は含まない。
.EXAMPLE
    Get-Recipient -Server dc01.corp.local
    Get-Recipient -Identity user@contoso.com -Server dc01.corp.local
    Get-Recipient -Filter "DisplayName -like '山田*'" -Server dc01.corp.local
#>
function Get-Recipient {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )
    try {
        # mailNickname があれば Exchange 受信者とみなす（typeDetails なし旧スキーマも含む）
        $baseFilter = '(mailNickname=*)'
        $f = ADSI_BuildRecipientFilter $baseFilter $Identity $LDAPFilter $Filter

        $attrs = $script:ADSI_RecipientCoreAttrs + @(
                   'msExchRecipientTypeDetails','msExchHideFromAddressLists',
                   'objectClass','homeMDB','targetAddress')

        ADSI_RecipientRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -LoadAttrs $attrs -ResultSetSize $ResultSetSize `
            -Timeout $Timeout -SearchBase $SearchBase -ProgressActivity 'Get-Recipient' |
        ForEach-Object {
            $oc       = @($_.objectClass)
            $proxies  = if ($null -ne $_.proxyAddresses) { @($_.proxyAddresses) } else { @() }
            $primary  = ADSI_ResolvePrimary $proxies $_.mail

            $typeDetails = ADSI_DecodeRecipientTypeDetails $_.msExchRecipientTypeDetails

            # コース分類（objectClass + homeMDB/targetAddress からざっくり判定）
            $dn = [string]$_.distinguishedName
            $ocLast = if ($oc.Count) { [string]$oc[-1] } else { $null }
            $recipientType = if ($ocLast -eq 'msExchDynamicDistributionList') {
                'DynamicDistributionGroup'
            } elseif ($ocLast -eq 'group') {
                'MailUniversalDistributionGroup'
            } elseif ($ocLast -eq 'contact') {
                'MailContact'
            } elseif ($_.homeMDB) {
                'UserMailbox'
            } elseif ($_.targetAddress) {
                'MailUser'
            } else {
                'MailUser'
            }

            [pscustomobject]@{
                Name                           = [string]$_.name
                Alias                          = [string]$_.mailNickname
                DisplayName                    = [string]$_.displayName
                PrimarySmtpAddress             = $primary
                RecipientType                  = $recipientType
                RecipientTypeDetails           = $typeDetails
                EmailAddresses                 = ADSI_SmtpAddresses $proxies
                HiddenFromAddressListsEnabled  = ADSI_HideFromAL $_.msExchHideFromAddressLists
                # OrganizationalUnit は EMS の "domain/OU" 形式と異なり親 DN を返す
                OrganizationalUnit             = ADSI_OuFromDn $dn
                DistinguishedName              = $dn
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-Recipient に失敗しました' }
}

# ============================================================
# Get-Mailbox
# ============================================================

<#
.SYNOPSIS
    メールボックスユーザーの一覧を取得する（ドメイン NC）
.DESCRIPTION
    homeMDB が設定されたユーザーオブジェクトをメールボックスとして返す。
    Exchange Management Shell の Get-Mailbox 相当の構成スナップショット。
    マウント状態・サイズ等の動的情報は含まない。
.EXAMPLE
    Get-Mailbox -Server dc01.corp.local
    Get-Mailbox -Identity yamada@contoso.com -Server dc01.corp.local
    Get-Mailbox -Filter "DisplayName -like '山田*'" -Server dc01.corp.local
#>
function Get-Mailbox {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )
    try {
        $baseFilter = '(&(objectCategory=person)(objectClass=user)(homeMDB=*))'
        $f = ADSI_BuildRecipientFilter $baseFilter $Identity $LDAPFilter $Filter

        $attrs = $script:ADSI_RecipientCoreAttrs + @(
                   'userPrincipalName','sAMAccountName','homeMDB',
                   'msExchRecipientTypeDetails','msExchHideFromAddressLists',
                   'msExchMailboxGuid',
                   'msDS-ConsistencyGuid','msExchArchiveGUID','msExchPoliciesExcluded')

        ADSI_RecipientRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -LoadAttrs $attrs -ResultSetSize $ResultSetSize `
            -Timeout $Timeout -SearchBase $SearchBase -ProgressActivity 'Get-Mailbox' |
        ForEach-Object {
            $proxies = if ($null -ne $_.proxyAddresses) { @($_.proxyAddresses) } else { @() }
            $primary = ADSI_ResolvePrimary $proxies $_.mail

            $dn = [string]$_.distinguishedName

            # msExchMailboxGuid はバイト配列 → GUID 変換
            $mbxGuid = $null
            if ($_.msExchMailboxGuid) {
                $mbxGuid = ADSI_BytesToGuid $_.msExchMailboxGuid
            }

            [pscustomobject]@{
                Name                          = [string]$_.name
                Alias                         = [string]$_.mailNickname
                DisplayName                   = [string]$_.displayName
                PrimarySmtpAddress            = $primary
                UserPrincipalName             = [string]$_.userPrincipalName
                SamAccountName                = [string]$_.sAMAccountName
                # Database は homeMDB DN の先頭 CN（例: "Mailbox Database 1"）
                Database                      = ADSI_LeafCn ([string]$_.homeMDB)
                # ServerName: homeMDB DN から確実に取れないため省略
                ServerName                    = $null
                ExchangeGuid                  = $mbxGuid
                ArchiveGuid                   = ADSI_BytesToGuid $_.'msExchArchiveGUID'
                # Entra Connect のソースアンカー（msDS-ConsistencyGuid の Base64）
                ImmutableId                   = ADSI_ImmutableId $_.'msDS-ConsistencyGuid'
                EmailAddressPolicyEnabled     = ADSI_EapEnabled $_.msExchPoliciesExcluded
                RecipientTypeDetails          = ADSI_DecodeRecipientTypeDetails $_.msExchRecipientTypeDetails
                EmailAddresses                = ADSI_SmtpAddresses $proxies
                HiddenFromAddressListsEnabled = ADSI_HideFromAL $_.msExchHideFromAddressLists
                OrganizationalUnit            = ADSI_OuFromDn $dn
                DistinguishedName             = $dn
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-Mailbox に失敗しました' }
}

# ============================================================
# Get-RemoteMailbox
# ============================================================

<#
.SYNOPSIS
    リモートメールボックス（Exchange Online ハイブリッド）の一覧を取得する
.DESCRIPTION
    msExchRemoteRecipientType が設定されたユーザーオブジェクトを返す。
    Exchange Management Shell の Get-RemoteMailbox 相当の構成スナップショット。
    RemoteRoutingAddress は targetAddress から smtp: プレフィックスを除いた形式で返す。
.EXAMPLE
    Get-RemoteMailbox -Server dc01.corp.local
    Get-RemoteMailbox -Identity user@contoso.com -Server dc01.corp.local
#>
function Get-RemoteMailbox {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )
    try {
        $baseFilter = '(&(objectCategory=person)(objectClass=user)(msExchRemoteRecipientType=*))'
        $f = ADSI_BuildRecipientFilter $baseFilter $Identity $LDAPFilter $Filter

        $attrs = $script:ADSI_RecipientCoreAttrs + @(
                   'userPrincipalName','sAMAccountName','targetAddress',
                   'msExchRemoteRecipientType','msExchRecipientTypeDetails',
                   'msExchHideFromAddressLists','msExchMailboxGuid',
                   'msDS-ConsistencyGuid','msExchArchiveGUID','msExchPoliciesExcluded')

        ADSI_RecipientRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -LoadAttrs $attrs -ResultSetSize $ResultSetSize `
            -Timeout $Timeout -SearchBase $SearchBase -ProgressActivity 'Get-RemoteMailbox' |
        ForEach-Object {
            $proxies = if ($null -ne $_.proxyAddresses) { @($_.proxyAddresses) } else { @() }
            $primary = ADSI_ResolvePrimary $proxies $_.mail

            # EMS の RemoteRoutingAddress は smtp: プレフィックスを除いたアドレス
            $targetRaw = [string]$_.targetAddress
            $remoteRoute = ADSI_StripSmtpPrefix $targetRaw

            $mbxGuid = $null
            if ($_.msExchMailboxGuid) { $mbxGuid = ADSI_BytesToGuid $_.msExchMailboxGuid }

            $dn = [string]$_.distinguishedName

            [pscustomobject]@{
                Name                          = [string]$_.name
                Alias                         = [string]$_.mailNickname
                DisplayName                   = [string]$_.displayName
                PrimarySmtpAddress            = $primary
                RemoteRoutingAddress          = $remoteRoute
                RemoteRecipientType           = ADSI_DecodeRemoteRecipientType $_.msExchRemoteRecipientType
                RecipientTypeDetails          = ADSI_DecodeRecipientTypeDetails $_.msExchRecipientTypeDetails
                ExchangeGuid                  = $mbxGuid
                # EXO アーカイブの GUID（ProvisionArchive との突き合わせ用）
                ArchiveGuid                   = ADSI_BytesToGuid $_.'msExchArchiveGUID'
                # Entra Connect のソースアンカー（msDS-ConsistencyGuid の Base64）
                ImmutableId                   = ADSI_ImmutableId $_.'msDS-ConsistencyGuid'
                EmailAddressPolicyEnabled     = ADSI_EapEnabled $_.msExchPoliciesExcluded
                UserPrincipalName             = [string]$_.userPrincipalName
                SamAccountName                = [string]$_.sAMAccountName
                EmailAddresses                = ADSI_SmtpAddresses $proxies
                HiddenFromAddressListsEnabled = ADSI_HideFromAL $_.msExchHideFromAddressLists
                OrganizationalUnit            = ADSI_OuFromDn $dn
                DistinguishedName             = $dn
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-RemoteMailbox に失敗しました' }
}

# ============================================================
# Get-MailUser
# ============================================================

<#
.SYNOPSIS
    メールユーザー（外部アドレスを持つユーザー）の一覧を取得する
.DESCRIPTION
    mailNickname と targetAddress があり、homeMDB と msExchRemoteRecipientType が
    ないユーザーオブジェクトを返す。Exchange Management Shell の Get-MailUser 相当。
    ExternalEmailAddress は targetAddress をそのまま（smtp: プレフィックス付き）返す。
.EXAMPLE
    Get-MailUser -Server dc01.corp.local
    Get-MailUser -Identity external@fabrikam.com -Server dc01.corp.local
#>
function Get-MailUser {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )
    try {
        $baseFilter = '(&(objectCategory=person)(objectClass=user)(mailNickname=*)(targetAddress=*)(!(homeMDB=*))(!(msExchRemoteRecipientType=*)))'
        $f = ADSI_BuildRecipientFilter $baseFilter $Identity $LDAPFilter $Filter

        $attrs = $script:ADSI_RecipientCoreAttrs + @(
                   'userPrincipalName','sAMAccountName','targetAddress',
                   'msExchRecipientTypeDetails','msExchHideFromAddressLists',
                   'msExchMailboxGuid',
                   'msDS-ConsistencyGuid','msExchPoliciesExcluded')

        ADSI_RecipientRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -LoadAttrs $attrs -ResultSetSize $ResultSetSize `
            -Timeout $Timeout -SearchBase $SearchBase -ProgressActivity 'Get-MailUser' |
        ForEach-Object {
            $proxies = if ($null -ne $_.proxyAddresses) { @($_.proxyAddresses) } else { @() }
            $primary = ADSI_ResolvePrimary $proxies $_.mail

            $mbxGuid = $null
            if ($_.msExchMailboxGuid) { $mbxGuid = ADSI_BytesToGuid $_.msExchMailboxGuid }

            $dn = [string]$_.distinguishedName

            [pscustomobject]@{
                Name                          = [string]$_.name
                Alias                         = [string]$_.mailNickname
                DisplayName                   = [string]$_.displayName
                PrimarySmtpAddress            = $primary
                # EMS の ExternalEmailAddress は targetAddress をそのまま返す（smtp: 付き）
                ExternalEmailAddress          = [string]$_.targetAddress
                RecipientTypeDetails          = ADSI_DecodeRecipientTypeDetails $_.msExchRecipientTypeDetails
                ExchangeGuid                  = $mbxGuid
                # Entra Connect のソースアンカー（msDS-ConsistencyGuid の Base64）
                ImmutableId                   = ADSI_ImmutableId $_.'msDS-ConsistencyGuid'
                EmailAddressPolicyEnabled     = ADSI_EapEnabled $_.msExchPoliciesExcluded
                UserPrincipalName             = [string]$_.userPrincipalName
                SamAccountName                = [string]$_.sAMAccountName
                EmailAddresses                = ADSI_SmtpAddresses $proxies
                HiddenFromAddressListsEnabled = ADSI_HideFromAL $_.msExchHideFromAddressLists
                OrganizationalUnit            = ADSI_OuFromDn $dn
                DistinguishedName             = $dn
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-MailUser に失敗しました' }
}

# ============================================================
# Get-MailContact
# ============================================================

<#
.SYNOPSIS
    メール連絡先（Mail Contact）の一覧を取得する
.DESCRIPTION
    mailNickname が設定されたコンタクトオブジェクトを返す。
    Exchange Management Shell の Get-MailContact 相当。
    ExternalEmailAddress は targetAddress をそのまま（smtp: プレフィックス付き）返す。
.EXAMPLE
    Get-MailContact -Server dc01.corp.local
    Get-MailContact -Identity external@fabrikam.com -Server dc01.corp.local
#>
function Get-MailContact {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )
    try {
        $baseFilter = '(&(objectClass=contact)(mailNickname=*))'
        $f = ADSI_BuildRecipientFilter $baseFilter $Identity $LDAPFilter $Filter

        $attrs = $script:ADSI_RecipientCoreAttrs + @(
                   'targetAddress','msExchRecipientTypeDetails',
                   'msExchHideFromAddressLists')

        ADSI_RecipientRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -LoadAttrs $attrs -ResultSetSize $ResultSetSize `
            -Timeout $Timeout -SearchBase $SearchBase -ProgressActivity 'Get-MailContact' |
        ForEach-Object {
            $proxies = if ($null -ne $_.proxyAddresses) { @($_.proxyAddresses) } else { @() }
            $primary = ADSI_ResolvePrimary $proxies $_.mail

            $dn = [string]$_.distinguishedName

            [pscustomobject]@{
                Name                          = [string]$_.name
                Alias                         = [string]$_.mailNickname
                DisplayName                   = [string]$_.displayName
                PrimarySmtpAddress            = $primary
                ExternalEmailAddress          = [string]$_.targetAddress
                RecipientTypeDetails          = ADSI_DecodeRecipientTypeDetails $_.msExchRecipientTypeDetails
                EmailAddresses                = ADSI_SmtpAddresses $proxies
                HiddenFromAddressListsEnabled = ADSI_HideFromAL $_.msExchHideFromAddressLists
                OrganizationalUnit            = ADSI_OuFromDn $dn
                DistinguishedName             = $dn
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-MailContact に失敗しました' }
}

# ============================================================
# Get-DistributionGroup
# ============================================================

<#
.SYNOPSIS
    配布グループ・メール対応セキュリティグループの一覧を取得する
.DESCRIPTION
    mailNickname が設定されたグループオブジェクトを返す。
    Exchange Management Shell の Get-DistributionGroup 相当。
    動的配布グループは Get-DynamicDistributionGroup で別途取得する。
.EXAMPLE
    Get-DistributionGroup -Server dc01.corp.local
    Get-DistributionGroup -Identity "All Staff" -Server dc01.corp.local
    Get-DistributionGroup -Filter "DisplayName -like 'HR*'" -Server dc01.corp.local
#>
function Get-DistributionGroup {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )
    try {
        $baseFilter = '(&(objectClass=group)(mailNickname=*))'
        $f = ADSI_BuildRecipientFilter $baseFilter $Identity $LDAPFilter $Filter

        $attrs = $script:ADSI_RecipientCoreAttrs + @(
                   'sAMAccountName','groupType','managedBy',
                   'msExchRecipientTypeDetails','msExchHideFromAddressLists')

        ADSI_RecipientRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -LoadAttrs $attrs -ResultSetSize $ResultSetSize `
            -Timeout $Timeout -SearchBase $SearchBase -ProgressActivity 'Get-DistributionGroup' |
        ForEach-Object {
            $proxies = if ($null -ne $_.proxyAddresses) { @($_.proxyAddresses) } else { @() }
            $primary = ADSI_ResolvePrimary $proxies $_.mail

            $dn = [string]$_.distinguishedName

            [pscustomobject]@{
                Name                          = [string]$_.name
                Alias                         = [string]$_.mailNickname
                DisplayName                   = [string]$_.displayName
                PrimarySmtpAddress            = $primary
                GroupType                     = ADSI_GroupScope $_.groupType
                GroupCategory                 = ADSI_GroupCategory $_.groupType
                RecipientTypeDetails          = ADSI_DecodeRecipientTypeDetails $_.msExchRecipientTypeDetails
                ManagedBy                     = ADSI_LeafCn ([string]$_.managedBy)
                SamAccountName                = [string]$_.sAMAccountName
                EmailAddresses                = ADSI_SmtpAddresses $proxies
                HiddenFromAddressListsEnabled = ADSI_HideFromAL $_.msExchHideFromAddressLists
                OrganizationalUnit            = ADSI_OuFromDn $dn
                DistinguishedName             = $dn
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-DistributionGroup に失敗しました' }
}

# ============================================================
# Get-DynamicDistributionGroup
# ============================================================

<#
.SYNOPSIS
    動的配布グループの一覧を取得する
.DESCRIPTION
    msExchDynamicDistributionList オブジェクトを返す。
    Exchange Management Shell の Get-DynamicDistributionGroup 相当。
    RecipientFilter（OPATH文字列）と LdapRecipientFilter（LDAPフィルター文字列）を
    AD から読んだ値そのまま返す。動的情報（実際のメンバー）は取得不可。
    msExchQueryFilter → RecipientFilter
    msExchDynamicDLFilter → LdapRecipientFilter（Microsoft Learn で確認済み）
    msExchDynamicDLBaseDN → RecipientContainer（Microsoft Learn で確認済み）
.EXAMPLE
    Get-DynamicDistributionGroup -Server dc01.corp.local
    Get-DynamicDistributionGroup -Identity "All Users" -Server dc01.corp.local
#>
function Get-DynamicDistributionGroup {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )
    try {
        $baseFilter = '(objectClass=msExchDynamicDistributionList)'
        $f = ADSI_BuildRecipientFilter $baseFilter $Identity $LDAPFilter $Filter

        $attrs = $script:ADSI_RecipientCoreAttrs + @(
                   'msExchQueryFilter','msExchDynamicDLFilter','msExchDynamicDLBaseDN',
                   'msExchHideFromAddressLists')

        ADSI_RecipientRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -LoadAttrs $attrs -ResultSetSize $ResultSetSize `
            -Timeout $Timeout -SearchBase $SearchBase -ProgressActivity 'Get-DynamicDistributionGroup' |
        ForEach-Object {
            $proxies = if ($null -ne $_.proxyAddresses) { @($_.proxyAddresses) } else { @() }
            $primary = ADSI_ResolvePrimary $proxies $_.mail

            [pscustomobject]@{
                Name                          = [string]$_.name
                Alias                         = [string]$_.mailNickname
                DisplayName                   = [string]$_.displayName
                PrimarySmtpAddress            = $primary
                # OPATH 文字列（EMS の -RecipientFilter で使う形式）をそのまま返す
                RecipientFilter               = [string]$_.msExchQueryFilter
                # LDAP フィルター文字列（属性名: msExchDynamicDLFilter、Microsoft Learn 確認済み）
                LdapRecipientFilter           = [string]$_.msExchDynamicDLFilter
                # 動的グループの検索基点 DN（属性名: msExchDynamicDLBaseDN、Microsoft Learn 確認済み）
                RecipientContainer            = [string]$_.msExchDynamicDLBaseDN
                EmailAddresses                = ADSI_SmtpAddresses $proxies
                HiddenFromAddressListsEnabled = ADSI_HideFromAL $_.msExchHideFromAddressLists
                DistinguishedName             = [string]$_.distinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-DynamicDistributionGroup に失敗しました' }
}

# ============================================================
# Get-DistributionGroupMember
# ============================================================

<#
.SYNOPSIS
    配布グループのメンバーを取得する（非再帰）
.DESCRIPTION
    メール対応グループの member 属性を展開して返す。
    EMS の Get-DistributionGroupMember と同様に非再帰（直接メンバーのみ）。
    1500件超の大規模グループは range 取得で対応する。
    各メンバーの Exchange 属性（alias, PrimarySmtpAddress 等）も解決する。
.EXAMPLE
    Get-DistributionGroupMember -Identity "All Staff" -Server dc01.corp.local
    Get-DistributionGroupMember -Identity "DL-HR@contoso.com" -Server dc01.corp.local
#>
function Get-DistributionGroupMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Identity,

        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )
    try {
        # まずグループ本体を特定
        $gFilter = ADSI_BuildRecipientFilter '(&(objectClass=group)(mailNickname=*))' $Identity $null $null
        $grp = ADSI_RecipientRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $gFilter -LoadAttrs @('distinguishedName','name') `
            -SearchBase $SearchBase -ProgressActivity 'Get-DistributionGroupMember (グループ解決中)' |
            Select-Object -First 1

        if (-not $grp) { throw "配布グループが見つかりません: $Identity" }

        $nc   = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $base = if ($SearchBase) { $SearchBase } else { $nc.Default }

        $conn = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $base
        try {
            # range 取得でメンバー DN をすべて取得
            $dns = ADSI_GetMemberDNsRanged -Conn $conn -GroupDN ([string]$grp.DistinguishedName) -ClientTimeoutSec $Timeout

            # DN 解決してオブジェクト情報取得（50件チャンク）
            $count  = 0
            $chunkSize = 50
            for ($i = 0; $i -lt $dns.Count; $i += $chunkSize) {
                if ($ResultSetSize -gt 0 -and $count -ge $ResultSetSize) {
                    Write-Warning "結果が上限 $ResultSetSize 件に達したため打ち切りました（-ResultSetSize で変更可）。"
                    break
                }

                $end   = [Math]::Min($i + $chunkSize - 1, $dns.Count - 1)
                $chunk = $dns[$i..$end]
                $ors   = ($chunk | ForEach-Object { "(distinguishedName=$(ADSI_EscapeLdapValue $_))" }) -join ''
                $mFilter = "(|$ors)"

                $mAttrs = $script:ADSI_RecipientCoreAttrs + @(
                            'msExchRecipientTypeDetails','objectClass','sAMAccountName')
                $s = ADSI_NewSearcher -SearchRoot $conn -Filter $mFilter -Scope Subtree -Properties $mAttrs
                $res = $null
                try {
                    $res = $s.FindAll()
                    foreach ($r in $res) {
                        if ($ResultSetSize -gt 0 -and $count -ge $ResultSetSize) { break }
                        $p = $r.Properties

                        $proxies = @($p['proxyaddresses'])
                        $primary = ADSI_PrimarySmtp $proxies
                        if (-not $primary -and $p.Contains('mail') -and $p['mail'].Count) {
                            $primary = [string]$p['mail'][0]
                        }

                        $oc = @($p['objectclass'])
                        $ocLast = if ($oc.Count) { [string]$oc[-1] } else { $null }

                        [pscustomobject]@{
                            Name                 = if ($p.Contains('name') -and $p['name'].Count)           { [string]$p['name'][0] }           else { $null }
                            Alias                = if ($p.Contains('mailnickname') -and $p['mailnickname'].Count) { [string]$p['mailnickname'][0] } else { $null }
                            DisplayName          = if ($p.Contains('displayname') -and $p['displayname'].Count)  { [string]$p['displayname'][0] }  else { $null }
                            PrimarySmtpAddress   = $primary
                            RecipientTypeDetails = ADSI_DecodeRecipientTypeDetails $(if ($p.Contains('msexchrecipienttypedetails') -and $p['msexchrecipienttypedetails'].Count) { $p['msexchrecipienttypedetails'][0] } else { $null })
                            SamAccountName       = if ($p.Contains('samaccountname') -and $p['samaccountname'].Count) { [string]$p['samaccountname'][0] } else { $null }
                            ObjectClass          = $ocLast
                            DistinguishedName    = if ($p.Contains('distinguishedname') -and $p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { $null }
                        }
                        $count++
                    }
                }
                finally {
                    if ($res) { $res.Dispose() }
                    $s.Dispose()
                }
            }
        }
        finally { $conn.Dispose() }
    }
    catch { ADSI_ThrowLdap $_ 'Get-DistributionGroupMember に失敗しました' }
}

# ============================================================
# ADSearch.Exchange.ps1
# Exchange の「構成情報」を AD（構成パーティション）から読み取る。
#
# 取得できるのは AD に格納された設定スナップショットのみ。
# メールの中身・キュー・サービス稼働状態などの動的情報は AD に
# 存在しないため取得できない。
#
# すべて読み取り専用。Exchange 未導入環境では警告して空を返す。
# ============================================================

# 構成パーティション内の Exchange 組織コンテナを返す
function ADSI_ExchangeOrgBase {
    param($Server, [switch]$UseSSL, [pscredential]$Credential)
    $nc = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
    "CN=Microsoft Exchange,CN=Services,$($nc.Config)"
}

# Exchange 組織サブツリーを objectClass で検索する共通処理（未導入は警告で空返し）
function ADSI_ExchangeRun {
    param(
        $Server, [switch]$UseSSL, [pscredential]$Credential,
        [string]$Filter,
        [string[]]$DefaultProps,
        [string[]]$Properties,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0,
        [string]$ProgressActivity
    )
    try {
        $base = ADSI_ExchangeOrgBase -Server $Server -UseSSL:$UseSSL -Credential $Credential
        ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase $base -SearchScope Subtree -NamingContext Config `
            -Filter $Filter -DefaultProps $DefaultProps -Properties $Properties `
            -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity $ProgressActivity
    }
    catch {
        if (ADSI_IsNoSuchObject $_.Exception.Message) {
            Write-Warning 'Exchange の構成情報が見つかりません（Exchange 未導入、または構成パーティションの読み取り権限がない可能性があります）。'
            return
        }
        throw
    }
}

# サーバー役割ビットマスクをデコード
function ADSI_DecodeExchangeRoles($v) {
    $n = ADSI_ToInt64 $v
    if ($null -eq $n) { return $null }
    $bits = @(
        @(2,  'Mailbox'),
        @(4,  'ClientAccess'),
        @(16, 'UnifiedMessaging'),
        @(32, 'HubTransport'),
        @(64, 'EdgeTransport')
    )
    $roles = @()
    foreach ($b in $bits) { if ($n -band $b[0]) { $roles += $b[1] } }
    if (-not $roles.Count) { return "Unknown($n)" }
    return ($roles -join ', ')
}

# networkAddress 多値から FQDN を抽出
function ADSI_ExchangeFqdn($networkAddress) {
    foreach ($a in @($networkAddress)) {
        if ($a -match '(?i)^ncacn_ip_tcp:(.+)$') { return $matches[1] }
    }
    foreach ($a in @($networkAddress)) {
        if ($a -match '(?i)^netbios:(.+)$') { return $matches[1] }
    }
    return $null
}

# DN の先頭 CN を取り出す
function ADSI_LeafCn([string]$dn) {
    if ([string]::IsNullOrWhiteSpace($dn)) { return $null }
    (($dn -split ',')[0] -replace '(?i)^CN=', '')
}

<#
.SYNOPSIS
    Exchange サーバーの一覧と役割・バージョンを取得する（構成情報）
.DESCRIPTION
    AD 構成パーティションの msExchExchangeServer オブジェクトを読み取る。
    Exchange Management Shell の Get-ExchangeServer 相当の構成スナップショット。
    サービス稼働状態などの動的情報は含まない。
.EXAMPLE
    Get-ExchangeServer -Server dc01.corp.local
#>
function Get-ExchangeServer {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchExchangeServer)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('serialNumber','msExchCurrentServerRoles','networkAddress','msExchServerSite') `
            -Timeout $Timeout -ProgressActivity 'Get-ExchangeServer' |
        ForEach-Object {
            [pscustomobject]@{
                Name              = $_.Name
                Fqdn              = ADSI_ExchangeFqdn $_.networkAddress
                ServerRole        = ADSI_DecodeExchangeRoles $_.msExchCurrentServerRoles
                Edition           = $_.serialNumber
                Site              = ADSI_LeafCn ([string]$_.msExchServerSite)
                DistinguishedName = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ExchangeServer に失敗しました' }
}

<#
.SYNOPSIS
    受信コネクタ（Receive Connector）の構成を取得する
.DESCRIPTION
    AD 構成パーティションの msExchSmtpReceiveConnector を読み取る。
#>
function Get-ReceiveConnector {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchSmtpReceiveConnector)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchSmtpReceiveBindings','msExchSmtpReceiveRemoteIPRanges','msExchSmtpReceiveType') `
            -Timeout $Timeout -ProgressActivity 'Get-ReceiveConnector' |
        ForEach-Object {
            # DN: CN=<connector>,CN=SMTP Receive Connectors,CN=Protocols,CN=<server>,...
            $owner = $null
            if ($_.DistinguishedName -match '(?i)CN=Protocols,CN=([^,]+),') { $owner = $matches[1] }
            [pscustomobject]@{
                Name              = $_.Name
                Server            = $owner
                Bindings          = $_.msExchSmtpReceiveBindings
                RemoteIPRanges    = $_.msExchSmtpReceiveRemoteIPRanges
                DistinguishedName = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ReceiveConnector に失敗しました' }
}

<#
.SYNOPSIS
    送信コネクタ（Send Connector）の構成を取得する
.DESCRIPTION
    AD 構成パーティションの msExchRoutingSMTPConnector を読み取る。
#>
function Get-SendConnector {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchRoutingSMTPConnector)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchSmartHostList','msExchSourceBridgeheadServersDN') `
            -Timeout $Timeout -ProgressActivity 'Get-SendConnector' |
        ForEach-Object {
            $bridges = @($_.msExchSourceBridgeheadServersDN) | Where-Object { $_ } | ForEach-Object { ADSI_LeafCn $_ }
            [pscustomobject]@{
                Name              = $_.Name
                SmartHosts        = $_.msExchSmartHostList
                SourceServers     = $bridges
                DistinguishedName = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-SendConnector に失敗しました' }
}

<#
.SYNOPSIS
    受理ドメイン（Accepted Domain）の構成を取得する
.DESCRIPTION
    AD 構成パーティションの msExchAcceptedDomain を読み取る。
#>
function Get-AcceptedDomain {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchAcceptedDomain)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchAcceptedDomainName','msExchAcceptedDomainFlags') `
            -Timeout $Timeout -ProgressActivity 'Get-AcceptedDomain' |
        ForEach-Object {
            $flags = ADSI_ToInt64 $_.msExchAcceptedDomainFlags
            $type  = if ($null -eq $flags) { $null } elseif ($flags -eq 0) { 'Authoritative' } else { "Relay($flags)" }
            $dom   = if ($_.msExchAcceptedDomainName) { $_.msExchAcceptedDomainName } else { $_.Name }
            [pscustomobject]@{
                Name              = $_.Name
                DomainName        = $dom
                DomainType        = $type
                DistinguishedName = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-AcceptedDomain に失敗しました' }
}

<#
.SYNOPSIS
    リモートドメイン（Remote Domain）の構成を取得する
.DESCRIPTION
    AD 構成パーティションの msExchDomainContentConfig を読み取る。
#>
function Get-RemoteDomain {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchDomainContentConfig)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchInteropDomain') `
            -Timeout $Timeout -ProgressActivity 'Get-RemoteDomain' |
        ForEach-Object {
            [pscustomobject]@{
                Name              = $_.Name
                DomainName        = if ($_.msExchInteropDomain) { $_.msExchInteropDomain } else { $_.Name }
                DistinguishedName = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-RemoteDomain に失敗しました' }
}

<#
.SYNOPSIS
    トランスポートルール（Transport Rule）の構成を取得する
.DESCRIPTION
    AD 構成パーティションの msExchTransportRule を読み取る。
    ルール本体はシリアライズされた XML（msExchTransportRuleXml）として
    格納されており、本コマンドは生 XML をそのまま返す（完全な復元は行わない）。
#>
function Get-TransportRule {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [switch]$IncludeXml,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchTransportRule)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchTransportRulePriority','msExchTransportRuleState','msExchTransportRuleXml') `
            -Timeout $Timeout -ProgressActivity 'Get-TransportRule' |
        ForEach-Object {
            $state = ADSI_ToInt64 $_.msExchTransportRuleState
            [pscustomobject]@{
                Name              = $_.Name
                Priority          = ADSI_ToInt64 $_.msExchTransportRulePriority
                State             = if ($null -eq $state) { $null } elseif ($state -eq 0) { 'Enabled' } else { 'Disabled' }
                RuleXml           = if ($IncludeXml) { [string]$_.msExchTransportRuleXml } else { $null }
                DistinguishedName = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-TransportRule に失敗しました' }
}

<#
.SYNOPSIS
    メールボックスデータベースの構成を取得する
.DESCRIPTION
    AD 構成パーティションの msExchPrivateMDB を読み取る。
    マウント状態・サイズ等の動的情報は含まない。
#>
function Get-MailboxDatabase {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchPrivateMDB)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchOwningServer') `
            -Timeout $Timeout -ProgressActivity 'Get-MailboxDatabase' |
        ForEach-Object {
            [pscustomobject]@{
                Name              = $_.Name
                Server            = ADSI_LeafCn ([string]$_.msExchOwningServer)
                DistinguishedName = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-MailboxDatabase に失敗しました' }
}

<#
.SYNOPSIS
    データベース可用性グループ（DAG）の構成を取得する
.DESCRIPTION
    AD 構成パーティションの msExchMDBAvailabilityGroup を読み取る。
#>
function Get-DatabaseAvailabilityGroup {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchMDBAvailabilityGroup)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchMDBAvailabilityGroupServersBL') `
            -Timeout $Timeout -ProgressActivity 'Get-DatabaseAvailabilityGroup' |
        ForEach-Object {
            $members = @($_.msExchMDBAvailabilityGroupServersBL) | Where-Object { $_ } | ForEach-Object { ADSI_LeafCn $_ }
            [pscustomobject]@{
                Name              = $_.Name
                Servers           = $members
                DistinguishedName = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-DatabaseAvailabilityGroup に失敗しました' }
}

# ============================================================
# 以下: アドレスリスト・OAB・メールアドレスポリシー（構成パーティション）
# ============================================================

# Exchange 組織内の "All Address Lists" コンテナ DN を返す
function ADSI_AddressListsBase {
    param($Server, [switch]$UseSSL, [pscredential]$Credential)
    $org = ADSI_ExchangeOrgBase -Server $Server -UseSSL:$UseSSL -Credential $Credential
    "CN=All Address Lists,CN=Address Lists Container,$org"
}

# Exchange 組織内の "All Global Address Lists" コンテナ DN を返す
function ADSI_GalBase {
    param($Server, [switch]$UseSSL, [pscredential]$Credential)
    $org = ADSI_ExchangeOrgBase -Server $Server -UseSSL:$UseSSL -Credential $Credential
    "CN=All Global Address Lists,CN=Address Lists Container,$org"
}

<#
.SYNOPSIS
    アドレスリスト（Address List）の構成を取得する（構成パーティション）
.DESCRIPTION
    AD 構成パーティションの "All Address Lists" コンテナ配下の
    addressBookContainer オブジェクトを読み取る。
    RecipientFilter は msExchQueryFilter（OPATH文字列）をそのまま返す。
    LdapRecipientFilter は purportedSearch（LDAP フィルター文字列）を返す。
    purportedSearch は Address-Book-Container クラスの標準属性（Microsoft Learn 確認済み）。
.EXAMPLE
    Get-AddressList -Server dc01.corp.local
    Get-AddressList -Identity "All Users" -Server dc01.corp.local
#>
function Get-AddressList {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=addressBookContainer)' $Identity $LDAPFilter $Filter -IdentityKind Name
        $base = ADSI_AddressListsBase -Server $Server -UseSSL:$UseSSL -Credential $Credential
        ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase $base -SearchScope Subtree -NamingContext Config `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchQueryFilter','purportedSearch') `
            -TimeoutSeconds $Timeout -ProgressActivity 'Get-AddressList' |
        ForEach-Object {
            [pscustomobject]@{
                Name                = $_.Name
                RecipientFilter     = [string]$_.msExchQueryFilter
                LdapRecipientFilter = [string]$_.purportedSearch
                Container           = ADSI_OuFromDn ([string]$_.DistinguishedName)
                DistinguishedName   = $_.DistinguishedName
            }
        }
    }
    catch {
        if (ADSI_IsNoSuchObject $_.Exception.Message) {
            Write-Warning 'アドレスリストの構成情報が見つかりません（Exchange 未導入、または構成パーティションの読み取り権限がない可能性があります）。'
            return
        }
        ADSI_ThrowLdap $_ 'Get-AddressList に失敗しました'
    }
}

<#
.SYNOPSIS
    グローバルアドレスリスト（GAL）の構成を取得する（構成パーティション）
.DESCRIPTION
    AD 構成パーティションの "All Global Address Lists" コンテナ配下の
    addressBookContainer オブジェクトを読み取る。
    RecipientFilter は msExchQueryFilter（OPATH文字列）をそのまま返す。
.EXAMPLE
    Get-GlobalAddressList -Server dc01.corp.local
#>
function Get-GlobalAddressList {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=addressBookContainer)' $Identity $LDAPFilter $Filter -IdentityKind Name
        $base = ADSI_GalBase -Server $Server -UseSSL:$UseSSL -Credential $Credential
        ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase $base -SearchScope Subtree -NamingContext Config `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchQueryFilter','purportedSearch') `
            -TimeoutSeconds $Timeout -ProgressActivity 'Get-GlobalAddressList' |
        ForEach-Object {
            [pscustomobject]@{
                Name                = $_.Name
                RecipientFilter     = [string]$_.msExchQueryFilter
                LdapRecipientFilter = [string]$_.purportedSearch
                Container           = ADSI_OuFromDn ([string]$_.DistinguishedName)
                DistinguishedName   = $_.DistinguishedName
            }
        }
    }
    catch {
        if (ADSI_IsNoSuchObject $_.Exception.Message) {
            Write-Warning 'グローバルアドレスリストの構成情報が見つかりません。'
            return
        }
        ADSI_ThrowLdap $_ 'Get-GlobalAddressList に失敗しました'
    }
}

<#
.SYNOPSIS
    オフラインアドレス帳（OAB）の構成を取得する（構成パーティション）
.DESCRIPTION
    AD 構成パーティションの msExchOAB オブジェクトを読み取る。
    IsDefault は msExchOABFlags の bit 1 で判定（ベストエフォート、属性名未公式）。
    AddressLists は msExchOABAddressLists の各 DN から先頭 CN を返す。
.EXAMPLE
    Get-OfflineAddressBook -Server dc01.corp.local
#>
function Get-OfflineAddressBook {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchOAB)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchOABAddressLists','msExchOABFlags') `
            -Timeout $Timeout -ProgressActivity 'Get-OfflineAddressBook' |
        ForEach-Object {
            $alList = @($_.msExchOABAddressLists) | Where-Object { $_ } | ForEach-Object { ADSI_LeafCn ([string]$_) }
            # msExchOABFlags bit 1 が IsDefault を示す（ベストエフォート、公式ドキュメント未確認）
            $flags = ADSI_ToInt64 $_.msExchOABFlags
            $isDefault = if ($null -ne $flags) { [bool]($flags -band 1) } else { $null }
            [pscustomobject]@{
                Name              = $_.Name
                AddressLists      = $alList
                IsDefault         = $isDefault
                DistinguishedName = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-OfflineAddressBook に失敗しました' }
}

<#
.SYNOPSIS
    電子メールアドレスポリシー（Email Address Policy）の構成を取得する（構成パーティション）
.DESCRIPTION
    AD 構成パーティションの msExchRecipientPolicy オブジェクトを読み取る。
    RecipientFilter は msExchQueryFilter（OPATH 文字列）をそのまま返す。
    LdapRecipientFilter は purportedSearch を返す。
    Priority は msExchPolicyOrder から取得（値が小さいほど優先度高）。
    EnabledEmailAddressTemplates は gatewayProxy 多値属性。
    これらの属性名はベストエフォート。公式ドキュメントに一覧なし。
.EXAMPLE
    Get-EmailAddressPolicy -Server dc01.corp.local
#>
function Get-EmailAddressPolicy {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [int]$Timeout = 0
    )
    try {
        $f = ADSI_BuildFinalFilter '(objectClass=msExchRecipientPolicy)' $Identity $LDAPFilter $Filter -IdentityKind Name
        ADSI_ExchangeRun -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -Filter $f -DefaultProps @('Name','DistinguishedName') `
            -Properties @('msExchQueryFilter','purportedSearch','msExchPolicyOrder','gatewayProxy') `
            -Timeout $Timeout -ProgressActivity 'Get-EmailAddressPolicy' |
        ForEach-Object {
            $templates = @($_.gatewayProxy) | Where-Object { $_ }
            [pscustomobject]@{
                Name                          = $_.Name
                # 優先度（小さい値が高優先）
                Priority                      = ADSI_ToInt64 $_.msExchPolicyOrder
                RecipientFilter               = [string]$_.msExchQueryFilter
                LdapRecipientFilter           = [string]$_.purportedSearch
                EnabledEmailAddressTemplates  = $templates
                DistinguishedName             = $_.DistinguishedName
            }
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-EmailAddressPolicy に失敗しました' }
}


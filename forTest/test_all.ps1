# === CONFIG LOAD START ===
$ConfigPath = Join-Path $PSScriptRoot 'test_all.config.json'

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "config ファイルが見つかりません: $ConfigPath"
}

$Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

$Server         = [string]$Config.Server
$SampleUser     = [string]$Config.SampleUser
$SampleGroup    = [string]$Config.SampleGroup
$SampleComputer = [string]$Config.SampleComputer
$SampleOU       = [string]$Config.SampleOU
$SampleDnsName  = [string]$Config.SampleDnsName
$SampleInvalidUser = [string]$Config.SampleInvalidUser

$UseSSLTest        = [bool]$Config.UseSSLTest
$UseCredentialTest = [bool]$Config.UseCredentialTest
$ConfiguredSearchBase = [string]$Config.SearchBase

if ([string]::IsNullOrWhiteSpace($Server)) {
    throw "test_all.config.json の Server が空です。"
}

if ([string]::IsNullOrWhiteSpace($SampleUser)) {
    throw "test_all.config.json の SampleUser が空です。"
}

if ([string]::IsNullOrWhiteSpace($SampleGroup)) {
    throw "test_all.config.json の SampleGroup が空です。"
}

if ([string]::IsNullOrWhiteSpace($SampleComputer)) {
    throw "test_all.config.json の SampleComputer が空です。"
}
# === CONFIG LOAD END ===
# ============================================================
# ADSearch 全関数・全主要スイッチ動作確認テスト
# 目的: 正確な値検証ではなく「コマンドが動くか/落ちるか」を見る
# ============================================================

# ============================================================
# MDI（Microsoft Defender for Identity）偵察検知対策
#
# このテストは以下の設計で MDI の
# "Security principal reconnaissance (LDAP)" アラートを回避する:
#   (1) 広域スキャンをテスト OU ($TestBase) に限定し、
#       ドメイン全体の Subtree スキャンを行わない
#   (2) 複数件を返しうるすべてのクエリに -ResultSetSize $Cap を付与し、
#       取得件数を最小限（$Cap = 3 件）に抑える
#   (3) 機微グループ（Administrators / Domain Admins /
#       Enterprise Admins 等）の再帰列挙は行わない
#
# SampleGroup には必ず専用のテストグループ（例: ADSearch-TestGroup）を
# 指定すること。機微グループを指定しないこと。
# ============================================================

Set-Location -LiteralPath $PSScriptRoot
# ADSearch 本体は親フォルダにある（forTest はテスト用サブフォルダ）
$AdsRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $AdsRoot 'ADSearch.ps1')

# Credential を試す場合
if ($UseCredentialTest) {
    $Cred = Get-Credential
}
else {
    $Cred = $null
}

# 共通 splat
$Common = @{
    Server = $Server
}

if ($Cred) {
    $Common.Credential = $Cred
}

$CommonSSL = @{
    Server = $Server
    UseSSL = $true
}

if ($Cred) {
    $CommonSSL.Credential = $Cred
}

# ===== テスト実行ヘルパー =====
$Results = New-Object System.Collections.Generic.List[object]

function Invoke-ADSearchCommandTest {
    param(
        [string]$Name,
        [scriptblock]$Script
    )

    try {
        $output = & $Script 2>&1

        $count = 0
        if ($null -ne $output) {
            $count = @($output).Count
        }

        $script:Results.Add([pscustomobject]@{
            Test   = $Name
            Result = 'Pass'
            Count  = $count
            Detail = ''
        })
    }
    catch {
        $script:Results.Add([pscustomobject]@{
            Test   = $Name
            Result = 'Fail'
            Count  = 0
            Detail = $_.Exception.Message
        })
    }
}

# ===== 事前確認 =====
Invoke-ADSearchCommandTest '00 Load / Public functions' {
    Invoke-ADSearchSelfTest
}

Invoke-ADSearchCommandTest '00 Connection / Server' {
    Invoke-ADSearchSelfTest -Server $Server
}

if ($UseSSLTest) {
    Invoke-ADSearchCommandTest '00 Connection / Server / UseSSL' {
        Invoke-ADSearchSelfTest @CommonSSL
    }
}

# SearchBase 自動取得
$SearchBase = $null
Invoke-ADSearchCommandTest '00 Resolve SearchBase by Get-ADDomain' {
    $d = Get-ADDomain @Common
    $script:SearchBase = $d.DistinguishedName
    $d
}

if (-not $SearchBase) {
    if (-not [string]::IsNullOrWhiteSpace([string]$Config.SearchBase)) {
        $SearchBase = [string]$Config.SearchBase
    }
    else {
        throw "SearchBase を自動取得できませんでした。test_all.config.json の SearchBase に DN を指定してください。例: DC=example,DC=local"
    }
}

# MDI 対策: 取得件数の上限（全 Filter/LDAPFilter 系クエリに適用）
$Cap = 3

# MDI 対策: 広域スキャンの基点をテスト OU に限定する
# テスト OU が設定されていればそこだけをスキャン、未設定時はドメインルートにフォールバック
if (-not [string]::IsNullOrWhiteSpace($SampleOU)) {
    $TestBase = $SampleOU
}
else {
    $TestBase = $SearchBase
}

# ============================================================
# Get-ADUser
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADUser / Identity' {
    Get-ADUser -Identity $SampleUser @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / Filter' {
    Get-ADUser -Filter "SamAccountName -eq '$SampleUser'" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / LDAPFilter' {
    Get-ADUser -LDAPFilter "(sAMAccountName=$SampleUser)" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / Properties' {
    Get-ADUser -Identity $SampleUser @Common -Properties memberOf,description | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / Properties *' {
    Get-ADUser -Identity $SampleUser @Common -Properties * | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / SearchBase' {
    Get-ADUser -LDAPFilter "(sAMAccountName=$SampleUser)" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / SearchScope Subtree' {
    Get-ADUser -LDAPFilter "(sAMAccountName=$SampleUser)" @Common -SearchBase $TestBase -SearchScope Subtree -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / SearchScope OneLevel' {
    # OneLevel テストはテスト OU を基点にする（ドメインルート全列挙を回避）
    Get-ADUser -LDAPFilter "(objectClass=user)" @Common -SearchBase $TestBase -SearchScope OneLevel -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / SearchScope Base' {
    $u = Get-ADUser -Identity $SampleUser @Common | Select-Object -First 1
    if ($u) {
        Get-ADUser -LDAPFilter "(objectClass=*)" @Common -SearchBase $u.DistinguishedName -SearchScope Base | Select-Object -First 1
    }
}

if ($UseSSLTest) {
    Invoke-ADSearchCommandTest 'Get-ADUser / UseSSL' {
        Get-ADUser -Identity $SampleUser @CommonSSL | Select-Object -First 1
    }
}

# ============================================================
# Get-ADGroup
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADGroup / Identity' {
    Get-ADGroup -Identity $SampleGroup @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroup / Filter' {
    Get-ADGroup -Filter "Name -eq '$SampleGroup'" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroup / LDAPFilter' {
    Get-ADGroup -LDAPFilter "(cn=$SampleGroup)" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroup / Properties' {
    Get-ADGroup -Identity $SampleGroup @Common -Properties member,memberOf,description | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroup / Properties *' {
    Get-ADGroup -Identity $SampleGroup @Common -Properties * | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroup / SearchBase' {
    Get-ADGroup -LDAPFilter "(cn=$SampleGroup)" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroup / SearchScope Subtree' {
    Get-ADGroup -LDAPFilter "(cn=$SampleGroup)" @Common -SearchBase $TestBase -SearchScope Subtree -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroup / SearchScope OneLevel' {
    # OneLevel テストはテスト OU を基点にする（ドメインルート全列挙を回避）
    Get-ADGroup -LDAPFilter "(objectCategory=group)" @Common -SearchBase $TestBase -SearchScope OneLevel -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroup / SearchScope Base' {
    $g = Get-ADGroup -Identity $SampleGroup @Common | Select-Object -First 1
    if ($g) {
        Get-ADGroup -LDAPFilter "(objectClass=*)" @Common -SearchBase $g.DistinguishedName -SearchScope Base | Select-Object -First 1
    }
}

if ($UseSSLTest) {
    Invoke-ADSearchCommandTest 'Get-ADGroup / UseSSL' {
        Get-ADGroup -Identity $SampleGroup @CommonSSL | Select-Object -First 1
    }
}

# ============================================================
# Get-ADGroupMember
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADGroupMember / Identity' {
    Get-ADGroupMember -Identity $SampleGroup @Common -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroupMember / Recursive' {
    # SampleGroup は必ず専用テストグループを指定すること。
    # Administrators / Domain Admins 等の機微グループを再帰列挙すると
    # MDI の偵察アラートが発生するため絶対に指定しないこと。
    Get-ADGroupMember -Identity $SampleGroup @Common -Recursive -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADGroupMember / SearchBase' {
    Get-ADGroupMember -Identity $SampleGroup @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

if ($UseSSLTest) {
    Invoke-ADSearchCommandTest 'Get-ADGroupMember / UseSSL' {
        Get-ADGroupMember -Identity $SampleGroup @CommonSSL -Recursive -ResultSetSize $Cap | Select-Object -First 1
    }
}

# ============================================================
# Get-ADComputer
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADComputer / Identity' {
    Get-ADComputer -Identity $SampleComputer @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADComputer / Filter' {
    Get-ADComputer -Filter "Name -eq '$SampleComputer'" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADComputer / LDAPFilter' {
    Get-ADComputer -LDAPFilter "(name=$SampleComputer)" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADComputer / Properties' {
    Get-ADComputer -Identity $SampleComputer @Common -Properties operatingSystem,dNSHostName | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADComputer / Properties *' {
    Get-ADComputer -Identity $SampleComputer @Common -Properties * | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADComputer / SearchBase' {
    Get-ADComputer -LDAPFilter "(name=$SampleComputer)" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADComputer / SearchScope Subtree' {
    Get-ADComputer -LDAPFilter "(objectCategory=computer)" @Common -SearchBase $TestBase -SearchScope Subtree -ResultSetSize $Cap | Select-Object -First 1
}

if ($UseSSLTest) {
    Invoke-ADSearchCommandTest 'Get-ADComputer / UseSSL' {
        Get-ADComputer -Identity $SampleComputer @CommonSSL | Select-Object -First 1
    }
}

# ============================================================
# Get-ADOrganizationalUnit
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADOrganizationalUnit / LDAPFilter' {
    Get-ADOrganizationalUnit -LDAPFilter "(objectCategory=organizationalUnit)" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADOrganizationalUnit / Filter' {
    Get-ADOrganizationalUnit -Filter "Name -like '*'" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADOrganizationalUnit / SearchBase' {
    Get-ADOrganizationalUnit -LDAPFilter "(objectCategory=organizationalUnit)" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADOrganizationalUnit / Properties' {
    Get-ADOrganizationalUnit -LDAPFilter "(objectCategory=organizationalUnit)" @Common -SearchBase $TestBase -ResultSetSize $Cap -Properties description,gPLink | Select-Object -First 1
}

# ============================================================
# Get-ADObject
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADObject / Identity user DN' {
    $u = Get-ADUser -Identity $SampleUser @Common | Select-Object -First 1
    if ($u) {
        Get-ADObject -Identity $u.DistinguishedName @Common | Select-Object -First 1
    }
}

Invoke-ADSearchCommandTest 'Get-ADObject / LDAPFilter' {
    Get-ADObject -LDAPFilter "(objectClass=*)" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADObject / Filter' {
    Get-ADObject -Filter "Name -like '*'" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADObject / Properties' {
    Get-ADObject -LDAPFilter "(objectClass=*)" @Common -SearchBase $TestBase -ResultSetSize $Cap -Properties objectClass,whenChanged | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADObject / Properties *' {
    # -Properties * は単一オブジェクト（Identity 指定）に限定する
    $u = Get-ADUser -Identity $SampleUser @Common | Select-Object -First 1
    if ($u) {
        Get-ADObject -Identity $u.DistinguishedName @Common -Properties * | Select-Object -First 1
    }
}

Invoke-ADSearchCommandTest 'Get-ADObject / IncludeDeletedObjects' {
    Get-ADObject -LDAPFilter "(isDeleted=TRUE)" @Common -IncludeDeletedObjects -ResultSetSize $Cap | Select-Object -First 1
}

# ============================================================
# Get-ADServiceAccount
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADServiceAccount / no filter' {
    Get-ADServiceAccount @Common -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADServiceAccount / LDAPFilter' {
    # gMSA は CN=Managed Service Accounts 配下でテスト OU 外のため、件数上限のみ（OU 限定しない）
    Get-ADServiceAccount -LDAPFilter "(objectClass=msDS-GroupManagedServiceAccount)" @Common -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADServiceAccount / Filter' {
    Get-ADServiceAccount -Filter "Name -like '*'" @Common -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADServiceAccount / Properties' {
    Get-ADServiceAccount @Common -ResultSetSize $Cap -Properties dNSHostName,description | Select-Object -First 1
}

# ============================================================
# Domain / Forest / DC
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADDomain / Server' {
    Get-ADDomain @Common
}

Invoke-ADSearchCommandTest 'Get-ADDomain / Identity' {
    $d = Get-ADDomain @Common
    if ($d -and $d.DNSRoot) {
        Get-ADDomain -Identity $d.DNSRoot @Common
    }
}

Invoke-ADSearchCommandTest 'Get-ADForest / Server' {
    Get-ADForest @Common
}

Invoke-ADSearchCommandTest 'Get-ADForest / Identity' {
    $f = Get-ADForest @Common
    if ($f -and $f.Name) {
        Get-ADForest -Identity $f.Name @Common
    }
}

Invoke-ADSearchCommandTest 'Get-ADDomainController / default' {
    Get-ADDomainController @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADDomainController / Discover' {
    Get-ADDomainController @Common -Discover | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADDomainController / Identity' {
    Get-ADDomainController -Identity $Server @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADDomainController / Filter' {
    Get-ADDomainController -Filter "Name -like '*'" @Common | Select-Object -First 1
}

if ($UseSSLTest) {
    Invoke-ADSearchCommandTest 'Get-ADDomain / UseSSL' {
        Get-ADDomain @CommonSSL
    }

    Invoke-ADSearchCommandTest 'Get-ADForest / UseSSL' {
        Get-ADForest @CommonSSL
    }

    Invoke-ADSearchCommandTest 'Get-ADDomainController / UseSSL' {
        Get-ADDomainController @CommonSSL | Select-Object -First 1
    }
}

# ============================================================
# Password Policy
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADDefaultDomainPasswordPolicy' {
    Get-ADDefaultDomainPasswordPolicy @Common
}

# ============================================================
# Trust
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADTrust / default' {
    Get-ADTrust @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADTrust / Identity if exists' {
    $t = Get-ADTrust @Common | Select-Object -First 1
    if ($t) {
        Get-ADTrust -Identity $t.Name @Common | Select-Object -First 1
    }
}

# ============================================================
# Replication
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADReplicationSite / default' {
    Get-ADReplicationSite @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADReplicationSite / Filter' {
    Get-ADReplicationSite -Filter "Name -like '*'" @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADReplicationSite / Identity if exists' {
    $x = Get-ADReplicationSite @Common | Select-Object -First 1
    if ($x) {
        Get-ADReplicationSite -Identity $x.Name @Common | Select-Object -First 1
    }
}

Invoke-ADSearchCommandTest 'Get-ADReplicationSiteLink / default' {
    Get-ADReplicationSiteLink @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADReplicationSiteLink / Filter' {
    Get-ADReplicationSiteLink -Filter "Name -like '*'" @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADReplicationSiteLink / Identity if exists' {
    $x = Get-ADReplicationSiteLink @Common | Select-Object -First 1
    if ($x) {
        Get-ADReplicationSiteLink -Identity $x.Name @Common | Select-Object -First 1
    }
}

Invoke-ADSearchCommandTest 'Get-ADReplicationSubnet / default' {
    Get-ADReplicationSubnet @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADReplicationSubnet / Filter' {
    Get-ADReplicationSubnet -Filter "Name -like '*'" @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADReplicationSubnet / Identity if exists' {
    $x = Get-ADReplicationSubnet @Common | Select-Object -First 1
    if ($x) {
        Get-ADReplicationSubnet -Identity $x.Name @Common | Select-Object -First 1
    }
}

Invoke-ADSearchCommandTest 'Get-ADReplicationConnection / default' {
    Get-ADReplicationConnection @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADReplicationConnection / Filter' {
    Get-ADReplicationConnection -Filter "Name -like '*'" @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADReplicationConnection / Identity if exists' {
    $x = Get-ADReplicationConnection @Common | Select-Object -First 1
    if ($x) {
        Get-ADReplicationConnection -Identity $x.Name @Common | Select-Object -First 1
    }
}

# ============================================================
# Get-ADGpoLink
# ============================================================

if (-not [string]::IsNullOrWhiteSpace($SampleOU)) {

    Invoke-ADSearchCommandTest 'Get-ADGpoLink / Target with GPO' {
        Get-ADGpoLink -Target $SampleOU @Common
    }

    Invoke-ADSearchCommandTest 'Get-ADGpoLink / Target explicit Server' {
        Get-ADGpoLink -Target $SampleOU -Server $Server
    }

}
else {
    $script:Results.Add([pscustomobject]@{
        Test   = 'Get-ADGpoLink / (SampleOU 未設定のためスキップ)'
        Result = 'Skip'
        Count  = 0
        Detail = 'test_all.config.json の SampleOU に OU DN を設定してください'
    })
}

# ============================================================
# Get-ADDnsRecord
# ============================================================

# MDI 対策: 広域 DNS スキャンは -Partition Domain に限定し Select-Object -First 5 で件数を抑える
Invoke-ADSearchCommandTest 'Get-ADDnsRecord / no filter (Domain partition)' {
    Get-ADDnsRecord -ComputerName $Server -Partition Domain | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-ADDnsRecord / Server alias' {
    # -Server エイリアス確認。広域スキャンを避けるため Domain パーティションに限定
    Get-ADDnsRecord -Server $Server -Partition Domain | Select-Object -First 1
}

# Forest パーティション（DomainDnsZones にない場合は 0 件・警告で Pass）
Invoke-ADSearchCommandTest 'Get-ADDnsRecord / Partition Forest' {
    # ForestDnsZones パーティションが存在しない環境では 0 件になることがある（Pass 扱い）
    Get-ADDnsRecord -ComputerName $Server -Partition Forest | Select-Object -First 5
}

if (-not [string]::IsNullOrWhiteSpace($SampleDnsName)) {

    Invoke-ADSearchCommandTest 'Get-ADDnsRecord / Name filter' {
        Get-ADDnsRecord -ComputerName $Server -Name $SampleDnsName
    }

}
else {
    $script:Results.Add([pscustomobject]@{
        Test   = 'Get-ADDnsRecord / Name filter (SampleDnsName 未設定のためスキップ)'
        Result = 'Skip'
        Count  = 0
        Detail = 'test_all.config.json の SampleDnsName にレコード名を設定してください'
    })
}


Invoke-ADSearchCommandTest 'Get-ADDnsRecord / ZoneName filter / has results' {
    $d = Get-ADDomain @Common
    if ($d) {
        $recs = @(Get-ADDnsRecord -ComputerName $Server -ZoneName $d.DNSRoot)
        if ($recs.Count -eq 0) { throw "ZoneName フィルターで 0 件: ゾーン=$($d.DNSRoot)" }
        $recs | Select-Object -First 5
    }
}

if (-not [string]::IsNullOrWhiteSpace($SampleDnsName)) {

    Invoke-ADSearchCommandTest 'Get-ADDnsRecord / Name filter / RecordType not empty' {
        $recs = @(Get-ADDnsRecord -ComputerName $Server -Name $SampleDnsName)
        if ($recs.Count -eq 0) { throw "レコードが 0 件" }
        $blank = $recs | Where-Object { [string]::IsNullOrWhiteSpace($_.RecordType) }
        if ($blank) { throw "RecordType が空のレコードあり: $($blank.Count) 件" }
        $recs
    }

    Invoke-ADSearchCommandTest 'Get-ADDnsRecord / Name filter / A record has IP' {
        $aRecs = @(Get-ADDnsRecord -ComputerName $Server -Name $SampleDnsName |
                   Where-Object { $_.RecordType -eq 'A' })
        if ($aRecs.Count -eq 0) { throw "A レコードが見つかりません: $SampleDnsName" }
        $noIp = $aRecs | Where-Object { [string]::IsNullOrWhiteSpace($_.Data) }
        if ($noIp) { throw "Data (IP) が空の A レコードあり: $($noIp.Count) 件" }
        $aRecs
    }

}
Invoke-ADSearchCommandTest 'Get-ADDnsRecord / ZoneName filter (domain zone)' {
    $d = Get-ADDomain @Common
    if ($d) {
        Get-ADDnsRecord -ComputerName $Server -ZoneName $d.DNSRoot | Select-Object -First 5
    }
}

# ============================================================
# Filter 強化（PowerShell 風・入れ子/混在）
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADUser / Filter nested and/or' {
    Get-ADUser -Filter "(Name -like '*' -or SamAccountName -like '*') -and Enabled -eq '$true'" @Common `
        -SearchBase $TestBase -ResultSetSize $Cap |
        Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / Filter -notlike' {
    Get-ADUser -Filter "Name -notlike 'zzzzz_nomatch*'" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

# ============================================================
# Get-ADGroupMember 強化（上限・タイムアウト）
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADGroupMember / Recursive + ResultSetSize' {
    # SampleGroup は専用テストグループを指定すること（機微グループ禁止）
    Get-ADGroupMember -Identity $SampleGroup @Common -Recursive -ResultSetSize $Cap
}

Invoke-ADSearchCommandTest 'Get-ADGroupMember / Recursive + Timeout' {
    Get-ADGroupMember -Identity $SampleGroup @Common -Recursive -Timeout 60 -ResultSetSize $Cap | Select-Object -First 5
}

# ============================================================
# Exchange 構成（未導入環境では 0 件・警告で Pass）
# ============================================================

Invoke-ADSearchCommandTest 'Get-ExchangeServer' {
    Get-ExchangeServer @Common
}

Invoke-ADSearchCommandTest 'Get-ReceiveConnector' {
    Get-ReceiveConnector @Common | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-SendConnector' {
    Get-SendConnector @Common | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-AcceptedDomain' {
    Get-AcceptedDomain @Common
}

Invoke-ADSearchCommandTest 'Get-RemoteDomain' {
    Get-RemoteDomain @Common
}

Invoke-ADSearchCommandTest 'Get-TransportRule' {
    Get-TransportRule @Common | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-MailboxDatabase' {
    Get-MailboxDatabase @Common
}

Invoke-ADSearchCommandTest 'Get-DatabaseAvailabilityGroup' {
    Get-DatabaseAvailabilityGroup @Common
}

# ============================================================
# Exchange 構成パーティション追加コマンド（v1.2、未導入環境は 0 件・警告で Pass）
# ============================================================

Invoke-ADSearchCommandTest 'Get-AddressList' {
    Get-AddressList @Common
}

Invoke-ADSearchCommandTest 'Get-GlobalAddressList' {
    Get-GlobalAddressList @Common
}

Invoke-ADSearchCommandTest 'Get-OfflineAddressBook' {
    Get-OfflineAddressBook @Common
}

Invoke-ADSearchCommandTest 'Get-EmailAddressPolicy' {
    Get-EmailAddressPolicy @Common
}

# ============================================================
# Exchange 受信者（ドメイン NC、v1.2）
# Exchange 未導入 or 受信者なし環境では 0 件で Pass
# ============================================================

Invoke-ADSearchCommandTest 'Get-Recipient / no filter' {
    Get-Recipient @Common -ResultSetSize $Cap | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-Recipient / Identity' {
    Get-Recipient -Identity $SampleUser @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-Recipient / Filter' {
    Get-Recipient -Filter "Name -like '*'" @Common -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-Recipient / LDAPFilter' {
    Get-Recipient -LDAPFilter '(mailNickname=*)' @Common -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-Mailbox / no filter' {
    Get-Mailbox @Common -ResultSetSize $Cap | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-Mailbox / Identity' {
    Get-Mailbox -Identity $SampleUser @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-Mailbox / Filter' {
    Get-Mailbox -Filter "Name -like '*'" @Common -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-RemoteMailbox / no filter' {
    Get-RemoteMailbox @Common -ResultSetSize $Cap | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-RemoteMailbox / Identity' {
    Get-RemoteMailbox -Identity $SampleUser @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-MailUser / no filter' {
    Get-MailUser @Common -ResultSetSize $Cap | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-MailContact / no filter' {
    Get-MailContact @Common -ResultSetSize $Cap | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-DistributionGroup / no filter' {
    Get-DistributionGroup @Common -ResultSetSize $Cap | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-DistributionGroup / Identity' {
    Get-DistributionGroup -Identity $SampleGroup @Common | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-DistributionGroup / Filter' {
    Get-DistributionGroup -Filter "Name -like '*'" @Common -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-DynamicDistributionGroup / no filter' {
    Get-DynamicDistributionGroup @Common -ResultSetSize $Cap | Select-Object -First 5
}

Invoke-ADSearchCommandTest 'Get-DistributionGroupMember / SampleGroup' {
    # SampleGroup がメール対応グループでない場合は空を返して Pass
    $g = Get-DistributionGroup -Identity $SampleGroup @Common | Select-Object -First 1
    if ($g) {
        Get-DistributionGroupMember -Identity $SampleGroup @Common -ResultSetSize $Cap | Select-Object -First 5
    }
}

# ============================================================
# v1.3 追加: アカウント状態 / RSAT 互換プロパティ / 診断
# ============================================================

Invoke-ADSearchCommandTest 'Get-ADUser / account-state 既定プロパティ' {
    Get-ADUser -Identity $SampleUser @Common |
        Select-Object -First 1 SamAccountName, Enabled, LockedOut, PasswordExpired, AccountExpirationDate
}

Invoke-ADSearchCommandTest 'Get-ADUser / RSAT 互換プロパティ' {
    Get-ADUser -Identity $SampleUser @Common `
        -Properties GivenName, Surname, Department, Title, LastBadPasswordAttempt, PasswordExpiryDate, PasswordNeverExpires |
        Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADComputer / MachinePasswordAge 既定プロパティ' {
    Get-ADComputer -Identity $SampleComputer @Common |
        Select-Object -First 1 Name, Enabled, MachinePasswordAge, PasswordLastSet
}

Invoke-ADSearchCommandTest 'Get-ADUserHealth / Identity' {
    Get-ADUserHealth -Identity $SampleUser @Common
}

Invoke-ADSearchCommandTest 'Get-ADUserHealth / Recursive' {
    Get-ADUserHealth -Identity $SampleUser @Common -Recursive
}

# ============================================================
# v1.3 追加: Search-ADAccount / Get-ADComputerHealth / primaryGroupID / 例外系
# ============================================================

Invoke-ADSearchCommandTest 'Search-ADAccount / AccountInactive DaysInactive UsersOnly' {
    Search-ADAccount -AccountInactive -DaysInactive 90 -UsersOnly @Common -SearchBase $TestBase -ResultSetSize $Cap
}

Invoke-ADSearchCommandTest 'Search-ADAccount / LockedOut' {
    Search-ADAccount -LockedOut @Common -SearchBase $TestBase -ResultSetSize $Cap
}

Invoke-ADSearchCommandTest 'Search-ADAccount / AccountDisabled' {
    Search-ADAccount -AccountDisabled @Common -SearchBase $TestBase -ResultSetSize $Cap
}

Invoke-ADSearchCommandTest 'Get-ADComputerHealth / Identity' {
    $h = Get-ADComputerHealth -Identity $SampleComputer @Common
    if (-not ($h.PSObject.Properties.Name -contains 'MachinePasswordStale')) {
        throw "MachinePasswordStale プロパティがありません"
    }
    if (-not ($h.PSObject.Properties.Name -contains 'DnsRegistered')) {
        throw "DnsRegistered プロパティがありません"
    }
    $h
}

Invoke-ADSearchCommandTest 'Get-ADUser / Filter PasswordLastSet -le 過去日' {
    $pastDate = (Get-Date).AddYears(-1).ToString('yyyy-MM-dd')
    Get-ADUser -Filter "PasswordLastSet -le '$pastDate'" @Common -SearchBase $TestBase -ResultSetSize $Cap | Select-Object -First 1
}

Invoke-ADSearchCommandTest 'Get-ADUser / Filter LockedOut -eq $true 例外' {
    $threw = $false
    try {
        Get-ADUser -Filter "LockedOut -eq `$true" @Common -SearchBase $TestBase -ResultSetSize $Cap | Out-Null
    }
    catch {
        $threw = $true
    }
    if (-not $threw) { throw "例外が発生しませんでした（サーバー側フィルター不可の明示エラーが期待される）" }
}

Invoke-ADSearchCommandTest 'Get-ADGroupMember / Domain Users primaryGroupID' {
    $members = @(Get-ADGroupMember -Identity 'Domain Users' @Common -ResultSetSize $Cap)
    if ($members.Count -eq 0) { throw "Domain Users のメンバーが 0 件です（primaryGroupID 対応が疑われます）" }
    $members
}

Invoke-ADSearchCommandTest 'Get-ADUser / Identity 存在しないSAM 例外' {
    $target = $SampleInvalidUser
    if ([string]::IsNullOrWhiteSpace($target)) { $target = 'zz-nonexistent-sam-99999' }
    $threw = $false
    try {
        Get-ADUser -Identity $target @Common | Out-Null
    }
    catch {
        $threw = $true
    }
    if (-not $threw) { throw "例外が発生しませんでした（Identity 厳格化が期待される）" }
}

# ============================================================
# 結果表示
# ============================================================

"`n==== Summary ===="
$Results |
    Group-Object Result |
    Select-Object Name,Count |
    Format-Table -AutoSize

"`n==== Failed ===="
$Results |
    Where-Object Result -eq 'Fail' |
    Format-Table Test, Detail -AutoSize -Wrap

"`n==== All Results ===="
$Results |
    Format-Table Test, Result, Count, Detail -AutoSize -Wrap

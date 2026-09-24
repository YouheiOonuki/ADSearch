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
Write-Host ''
if ($script:fail -eq 0) {
    Write-Host "すべて OK（$($script:count) 件）" -ForegroundColor Green
    Get-Module ADSearch | Remove-Module
    exit 0
}
Write-Host "NG が $($script:fail) 件あります（全 $($script:count) 件）" -ForegroundColor Red
Get-Module ADSearch | Remove-Module
exit 1

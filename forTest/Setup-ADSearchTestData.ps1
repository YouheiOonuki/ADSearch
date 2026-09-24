# ============================================================
# Setup-ADSearchTestData.ps1
# ADSearch test_all.ps1 用テストデータ作成スクリプト
#
# 前提:
#   - DC 上で Domain Admins 権限で実行すること
#   - ActiveDirectory / GroupPolicy モジュールが利用可能なこと
#   - このスクリプトは ADSearch フォルダと同じ場所に置くこと
#
# 後片付け: Cleanup-ADSearchTestData.ps1 で全削除
# ============================================================

#Requires -Modules ActiveDirectory, GroupPolicy

$ErrorActionPreference = 'Stop'

$domain   = Get-ADDomain
$dn       = $domain.DistinguishedName
$dnsRoot  = $domain.DNSRoot
$siteName = (Get-ADReplicationSite | Select-Object -First 1).Name

Write-Host "ドメイン: $dnsRoot ($dn)"
Write-Host "サイト  : $siteName"
Write-Host ""

# ============================================================
# 1. テスト用 OU（SearchScope OneLevel 用ユーザー/グループも収容）
# ============================================================
Write-Host "[1] テスト OU 作成..."

$ouName = 'ADSearchTest'
$ouDN   = "OU=$ouName,$dn"

if (-not (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $ouName -Path $dn -ProtectedFromAccidentalDeletion $false
    Write-Host "  作成: $ouDN"
}
else {
    Write-Host "  既存: $ouDN"
}

# ============================================================
# 2. テスト用ユーザー/グループ
#    テスト OU 内に配置する（MDI 対策で test_all の検索をテスト OU に
#    限定するため。ここを $dn=ドメインルートにすると OU スコープ検索で
#    見つからなくなる）。
# ============================================================
Write-Host "[2] テスト用ユーザー/グループ作成..."

if (-not (Get-ADUser -Filter "SamAccountName -eq 'adsearch-ol'" -ErrorAction SilentlyContinue)) {
    New-ADUser -Name 'ADSearch-OLUser' -SamAccountName 'adsearch-ol' -Path $ouDN
    Write-Host "  ユーザー作成: CN=ADSearch-OLUser,$ouDN"
}
else {
    Write-Host "  既存: adsearch-ol"
}

if (-not (Get-ADGroup -Filter "SamAccountName -eq 'adsearch-olgrp'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name 'ADSearch-OLGroup' -SamAccountName 'adsearch-olgrp' -GroupScope Global -Path $ouDN
    Write-Host "  グループ作成: CN=ADSearch-OLGroup,$ouDN"
}
else {
    Write-Host "  既存: adsearch-olgrp"
}

# ============================================================
# 3. GPO 作成 + OU へリンク（有効・強制の両方）
# ============================================================
Write-Host "[3] GPO 作成・リンク..."

foreach ($gpoName in @('ADSearch-TestGPO1', 'ADSearch-TestGPO2')) {
    if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $gpoName | Out-Null
        Write-Host "  GPO 作成: $gpoName"
    }
    else {
        Write-Host "  既存: $gpoName"
    }
}

# リンク（GPO1=有効, GPO2=強制）
New-GPLink -Name 'ADSearch-TestGPO1' -Target $ouDN -ErrorAction SilentlyContinue | Out-Null
New-GPLink -Name 'ADSearch-TestGPO2' -Target $ouDN -Enforced Yes -ErrorAction SilentlyContinue | Out-Null
Write-Host "  リンク完了: $ouDN"

# ============================================================
# 4. gMSA 作成
# ============================================================
Write-Host "[4] gMSA 作成..."

# 既存の KDS ルートキーをすべて削除してから再作成する
# （-EffectiveImmediately で作られた不良キーが残っていると Bad Key になるため）
$rDse        = Get-ADRootDSE
$kdsBase     = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($rDse.configurationNamingContext)"
$existingKeys = @(Get-ADObject -SearchBase $kdsBase -Filter * -SearchScope OneLevel -ErrorAction SilentlyContinue)
if ($existingKeys.Count -gt 0) {
    $existingKeys | ForEach-Object { Remove-ADObject -Identity $_ -Confirm:$false }
    Write-Host "  既存 KDS ルートキー削除: $($existingKeys.Count) 件"
}
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
Write-Host "  KDS ルートキー作成（EffectiveTime: -10h）"

if (-not (Get-ADServiceAccount -Filter "Name -eq 'ADSearch-gMSA'" -ErrorAction SilentlyContinue)) {
    New-ADServiceAccount `
        -Name 'ADSearch-gMSA' `
        -DNSHostName "adsearch-gmsa.$dnsRoot" `
        -PrincipalsAllowedToRetrieveManagedPassword 'Domain Computers'
    Write-Host "  gMSA 作成: ADSearch-gMSA"
}
else {
    Write-Host "  既存: ADSearch-gMSA"
}

# ============================================================
# 5. Fine-Grained Password Policy（PSO）作成
# ============================================================
Write-Host "[5] PSO 作成..."

if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'ADSearch-TestPSO'" -ErrorAction SilentlyContinue)) {
    New-ADFineGrainedPasswordPolicy `
        -Name 'ADSearch-TestPSO' `
        -Precedence 100 `
        -MinPasswordLength 8 `
        -PasswordHistoryCount 5 `
        -ComplexityEnabled $true `
        -LockoutThreshold 5 `
        -LockoutDuration '0:30:00' `
        -LockoutObservationWindow '0:30:00' `
        -MaxPasswordAge '90.00:00:00' `
        -MinPasswordAge '1.00:00:00' `
        -ReversibleEncryptionEnabled $false
    Write-Host "  PSO 作成: ADSearch-TestPSO"
}
else {
    Write-Host "  既存: ADSearch-TestPSO"
}

# PSO の適用対象にユーザーを追加
Add-ADFineGrainedPasswordPolicySubject -Identity 'ADSearch-TestPSO' -Subjects 'adsearch-ol' -ErrorAction SilentlyContinue
Write-Host "  PSO 適用対象: adsearch-ol"

# ============================================================
# 6. AD レプリケーションサブネット作成
# ============================================================
Write-Host "[6] サブネット作成..."

if (-not (Get-ADReplicationSubnet -Filter "Name -eq '192.168.200.0/24'" -ErrorAction SilentlyContinue)) {
    New-ADReplicationSubnet -Name '192.168.200.0/24' -Site $siteName -Location 'ADSearch Test'
    Write-Host "  サブネット作成: 192.168.200.0/24"
}
else {
    Write-Host "  既存: 192.168.200.0/24"
}

# ============================================================
# 7. 削除済みオブジェクト（IncludeDeletedObjects テスト用）
# ============================================================
Write-Host "[7] 削除済みオブジェクト作成..."

$delUserName = 'ADSearch-DelTest'
$delUserDN   = "CN=$delUserName,$dn"

# 既存の同名ユーザーを削除
$existing = Get-ADUser -Filter "Name -eq '$delUserName'" -ErrorAction SilentlyContinue
if ($existing) {
    Remove-ADUser -Identity $existing -Confirm:$false
}

New-ADUser -Name $delUserName -SamAccountName 'adsearch-del' -Path $dn
Start-Sleep -Milliseconds 500
Remove-ADObject -Identity "CN=$delUserName,$dn" -Confirm:$false
Write-Host "  ユーザー作成→削除: $delUserName"
Write-Host "  ※ AD ごみ箱が有効な場合のみ IncludeDeletedObjects で取得できます"

# ============================================================
# 8. config 更新
# ============================================================
Write-Host "[8] test_all.config.json 更新..."

$configPath = Join-Path $PSScriptRoot 'test_all.config.json'
$config = Get-Content $configPath -Raw | ConvertFrom-Json

$config.SampleOU      = $ouDN
$config.SampleDnsName = ($env:COMPUTERNAME).ToLower()

$config | ConvertTo-Json -Depth 3 |
    Set-Content -LiteralPath $configPath -Encoding UTF8

Write-Host "  SampleOU      : $($config.SampleOU)"
Write-Host "  SampleDnsName : $($config.SampleDnsName)"

# ============================================================
Write-Host ""
Write-Host "完了。test_all.ps1 を再実行してください。"
Write-Host "後片付け: .\Cleanup-ADSearchTestData.ps1"

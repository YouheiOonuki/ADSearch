# ============================================================
# Cleanup-ADSearchTestData.ps1
# Setup-ADSearchTestData.ps1 で作成したテストデータの削除
#
# 前提: DC 上で Domain Admins 権限で実行すること
# ============================================================

#Requires -Modules ActiveDirectory, GroupPolicy

$ErrorActionPreference = 'Continue'

$domain = Get-ADDomain
$dn     = $domain.DistinguishedName

Write-Host "テストデータ削除開始..."

# GPO リンク解除・GPO 削除
foreach ($gpoName in @('ADSearch-TestGPO1', 'ADSearch-TestGPO2')) {
    try {
        $ouDN = "OU=ADSearchTest,$dn"
        Remove-GPLink -Name $gpoName -Target $ouDN -ErrorAction SilentlyContinue
        Remove-GPO   -Name $gpoName -ErrorAction SilentlyContinue
        Write-Host "  GPO 削除: $gpoName"
    }
    catch { Write-Host "  スキップ: $gpoName ($($_.Exception.Message))" }
}

# テスト OU 内のオブジェクトと OU 本体を削除
try {
    Get-ADObject -SearchBase "OU=ADSearchTest,$dn" -Filter * |
        Sort-Object { $_.DistinguishedName.Length } -Descending |
        Remove-ADObject -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ADOrganizationalUnit -Identity "OU=ADSearchTest,$dn" -Confirm:$false
    Write-Host "  OU 削除: OU=ADSearchTest,$dn"
}
catch { Write-Host "  スキップ: OU ($($_.Exception.Message))" }

# ドメインルート直下の OneLevel テスト用オブジェクト
foreach ($sam in @('adsearch-ol', 'adsearch-olgrp', 'adsearch-del')) {
    try {
        $obj = Get-ADObject -Filter "sAMAccountName -eq '$sam'" -ErrorAction SilentlyContinue
        if ($obj) {
            Remove-ADObject -Identity $obj -Confirm:$false
            Write-Host "  削除: $sam"
        }
    }
    catch { Write-Host "  スキップ: $sam ($($_.Exception.Message))" }
}

# gMSA
try {
    Remove-ADServiceAccount -Identity 'ADSearch-gMSA' -Confirm:$false
    Write-Host "  gMSA 削除: ADSearch-gMSA"
}
catch { Write-Host "  スキップ: ADSearch-gMSA ($($_.Exception.Message))" }

# PSO
try {
    Remove-ADFineGrainedPasswordPolicy -Identity 'ADSearch-TestPSO' -Confirm:$false
    Write-Host "  PSO 削除: ADSearch-TestPSO"
}
catch { Write-Host "  スキップ: ADSearch-TestPSO ($($_.Exception.Message))" }

# サブネット
try {
    Remove-ADReplicationSubnet -Identity '192.168.200.0/24' -Confirm:$false
    Write-Host "  サブネット削除: 192.168.200.0/24"
}
catch { Write-Host "  スキップ: 192.168.200.0/24 ($($_.Exception.Message))" }

# config のテスト固有設定をリセット
$configPath = Join-Path $PSScriptRoot 'test_all.config.json'
if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    $config.SampleOU      = ''
    $config.SampleDnsName = ''
    $config | ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $configPath -Encoding UTF8
    Write-Host "  config リセット: SampleOU, SampleDnsName"
}

Write-Host ""
Write-Host "削除完了。"

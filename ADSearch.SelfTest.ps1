function Invoke-ADSearchSelfTest {
    [CmdletBinding()]
    param(
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SampleGroup = 'Domain Admins'
    )

    $rows = New-Object System.Collections.Generic.List[object]

    function Add-ADSearchSelfTestRow {
        param(
            [string]$Test,
            [string]$Result,
            [string]$Detail
        )

        $rows.Add([pscustomobject]@{
            Test   = $Test
            Result = $Result
            Detail = $Detail
        })
    }

    # 公開関数の真実源は ADSearch.psd1。可能ならそこから読み、ロード形態で見つからなければ
    # 従来の Get-Command 可用性チェックにフォールバックする。
    # -Server 未指定時はこのロード確認のみ実施し、ドメインに一切アクセスしない。
    $moduleBase = $null
    $mod = Get-Module ADSearch
    if ($mod) { $moduleBase = $mod.ModuleBase }
    elseif ($PSScriptRoot) { $moduleBase = $PSScriptRoot }
    $public = $null
    if ($moduleBase) {
        $psd1 = Join-Path $moduleBase 'ADSearch.psd1'
        if (Test-Path -LiteralPath $psd1) {
            $public = (Import-PowerShellDataFile $psd1).FunctionsToExport
        }
    }
    $publicFromManifest = [bool]$public
    if (-not $public) {
        # フォールバック: psd1 を特定できないロード形態。既知の公開関数名で可用性のみ確認する。
        $public = @(
            # AD オブジェクト
            'Get-ADUser',
            'Get-ADGroup',
            'Get-ADGroupMember',
            'Get-ADComputer',
            'Get-ADOrganizationalUnit',
            'Get-ADObject',
            'Get-ADServiceAccount',
            # ドメイン / フォレスト / DC / 信頼 / レプリケーション
            'Get-ADDomain',
            'Get-ADDomainController',
            'Get-ADForest',
            'Get-ADDefaultDomainPasswordPolicy',
            'Get-ADTrust',
            'Get-ADReplicationSite',
            'Get-ADReplicationSiteLink',
            'Get-ADReplicationSubnet',
            'Get-ADReplicationConnection',
            # 追加機能
            'Get-ADGpoLink',
            'Get-ADDnsRecord',
            # 診断
            'Get-ADUserHealth',
            'Search-ADAccount',
            'Get-ADComputerHealth',
            # Exchange 構成（AD 構成パーティション）
            'Get-ExchangeServer',
            'Get-ReceiveConnector',
            'Get-SendConnector',
            'Get-AcceptedDomain',
            'Get-RemoteDomain',
            'Get-TransportRule',
            'Get-MailboxDatabase',
            'Get-DatabaseAvailabilityGroup',
            'Get-AddressList',
            'Get-GlobalAddressList',
            'Get-OfflineAddressBook',
            'Get-EmailAddressPolicy',
            # Exchange 受信者（AD ドメイン NC）
            'Get-Recipient',
            'Get-Mailbox',
            'Get-RemoteMailbox',
            'Get-MailUser',
            'Get-MailContact',
            'Get-DistributionGroup',
            'Get-DynamicDistributionGroup',
            'Get-DistributionGroupMember'
        )
    }

    $missing = @(
        $public | Where-Object {
            -not (Get-Command $_ -ErrorAction SilentlyContinue)
        }
    )

    $label = "公開関数ロード ($($public.Count))"
    if ($missing.Count -gt 0) {
        Add-ADSearchSelfTestRow $label 'Fail' ('未ロード: ' + ($missing -join ', '))
    }
    else {
        Add-ADSearchSelfTestRow $label 'Pass' "全 $($public.Count) 関数 OK"
    }

    if ($publicFromManifest) {
        $mod2 = Get-Module ADSearch
        if ($mod2) {
            $effective = @($mod2.ExportedCommands.Keys)
            $declared = @($public)
            $notExported = @($declared | Where-Object { $effective -notcontains $_ })
            $extraExported = @($effective | Where-Object { $declared -notcontains $_ })
            if ($notExported.Count -eq 0 -and $extraExported.Count -eq 0) {
                Add-ADSearchSelfTestRow 'エクスポート整合' 'Pass' "psd1 と ExportedCommands 一致 ($($declared.Count))"
            }
            else {
                $detail = @()
                if ($notExported.Count -gt 0) { $detail += 'psd1にあり未エクスポート: ' + ($notExported -join ', ') }
                if ($extraExported.Count -gt 0) { $detail += 'エクスポート済みだがpsd1外: ' + ($extraExported -join ', ') }
                Add-ADSearchSelfTestRow 'エクスポート整合' 'Fail' ($detail -join ' / ')
            }
        }
        else {
            Add-ADSearchSelfTestRow 'エクスポート整合' 'Pass' '(module未ロードのためエクスポート整合はスキップ)'
        }
    }
    else {
        Add-ADSearchSelfTestRow 'エクスポート整合' 'Pass' '(module未ロードのためエクスポート整合はスキップ)'
    }

    if ([string]::IsNullOrWhiteSpace($Server)) {
        Add-ADSearchSelfTestRow '実 AD テスト' 'Pass' '(-Server 未指定のためスキップ)'
        return $rows
    }

    try {
        $c = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $c.Dispose()
        Add-ADSearchSelfTestRow 'New-ADSConnection 接続' 'Pass' '接続成功'
    }
    catch {
        Add-ADSearchSelfTestRow 'New-ADSConnection 接続' 'Fail' $_.Exception.Message
    }

    try {
        $u = Get-ADUser -LDAPFilter '(sAMAccountName=*)' -Server $Server -UseSSL:$UseSSL -Credential $Credential |
            Select-Object -First 1

        if ($u) {
            Add-ADSearchSelfTestRow 'Get-ADUser -LDAPFilter' 'Pass' $u.SamAccountName
        }
        else {
            Add-ADSearchSelfTestRow 'Get-ADUser -LDAPFilter' 'Pass' '検索結果 0 件'
        }
    }
    catch {
        Add-ADSearchSelfTestRow 'Get-ADUser -LDAPFilter' 'Fail' $_.Exception.Message
    }

    try {
        $g = Get-ADGroup -LDAPFilter '(cn=*)' -Server $Server -UseSSL:$UseSSL -Credential $Credential |
            Select-Object -First 1

        if ($g) {
            Add-ADSearchSelfTestRow 'Get-ADGroup -LDAPFilter' 'Pass' $g.Name
        }
        else {
            Add-ADSearchSelfTestRow 'Get-ADGroup -LDAPFilter' 'Pass' '検索結果 0 件'
        }
    }
    catch {
        Add-ADSearchSelfTestRow 'Get-ADGroup -LDAPFilter' 'Fail' $_.Exception.Message
    }

    try {
        $m = Get-ADGroupMember -Identity $SampleGroup -Recursive -Server $Server -UseSSL:$UseSSL -Credential $Credential |
            Select-Object -First 1

        if ($m) {
            Add-ADSearchSelfTestRow 'Get-ADGroupMember -Recursive' 'Pass' $m.Name
        }
        else {
            Add-ADSearchSelfTestRow 'Get-ADGroupMember -Recursive' 'Pass' '検索結果 0 件'
        }
    }
    catch {
        Add-ADSearchSelfTestRow 'Get-ADGroupMember -Recursive' 'Fail' $_.Exception.Message
    }

    return $rows
}



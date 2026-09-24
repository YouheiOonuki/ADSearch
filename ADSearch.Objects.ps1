function Get-ADUser {
    [CmdletBinding(DefaultParameterSetName = 'Filter')]
    param(
        [Parameter(Position = 0, ParameterSetName = 'Identity')]
        [string]$Identity,

        [Parameter(ParameterSetName = 'Filter')]
        [string]$Filter,

        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [ValidateSet('Base','OneLevel','Subtree')]
        [string]$SearchScope = 'Subtree',
        [string[]]$Properties,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )

    try {
        $f = ADSI_BuildFinalFilter '(&(objectCategory=person)(objectClass=user))' $Identity $LDAPFilter $Filter
        if ($Identity) {
            $r = @(ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                    -SearchBase $SearchBase -SearchScope $SearchScope `
                    -Properties $Properties -Filter $f `
                    -DefaultProps $script:ADSI_DefaultProperties.User `
                    -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADUser')
            if ($r.Count -eq 0) { throw "オブジェクトが見つかりません (Identity='$Identity')" }
            $r
        }
        else {
            ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                -SearchBase $SearchBase -SearchScope $SearchScope `
                -Properties $Properties -Filter $f `
                -DefaultProps $script:ADSI_DefaultProperties.User `
                -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADUser'
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADUser に失敗しました' }
}

function Get-ADGroup {
    [CmdletBinding(DefaultParameterSetName = 'Filter')]
    param(
        [Parameter(Position = 0, ParameterSetName = 'Identity')]
        [string]$Identity,

        [Parameter(ParameterSetName = 'Filter')]
        [string]$Filter,

        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [ValidateSet('Base','OneLevel','Subtree')]
        [string]$SearchScope = 'Subtree',
        [string[]]$Properties,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )

    try {
        $f = ADSI_BuildFinalFilter '(objectCategory=group)' $Identity $LDAPFilter $Filter
        if ($Identity) {
            $r = @(ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                    -SearchBase $SearchBase -SearchScope $SearchScope `
                    -Properties $Properties -Filter $f `
                    -DefaultProps $script:ADSI_DefaultProperties.Group `
                    -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADGroup')
            if ($r.Count -eq 0) { throw "オブジェクトが見つかりません (Identity='$Identity')" }
            $r
        }
        else {
            ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                -SearchBase $SearchBase -SearchScope $SearchScope `
                -Properties $Properties -Filter $f `
                -DefaultProps $script:ADSI_DefaultProperties.Group `
                -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADGroup'
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADGroup に失敗しました' }
}

function Get-ADComputer {
    [CmdletBinding(DefaultParameterSetName = 'Filter')]
    param(
        [Parameter(Position = 0, ParameterSetName = 'Identity')]
        [string]$Identity,

        [Parameter(ParameterSetName = 'Filter')]
        [string]$Filter,

        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [ValidateSet('Base','OneLevel','Subtree')]
        [string]$SearchScope = 'Subtree',
        [string[]]$Properties,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )

    try {
        $f = ADSI_BuildFinalFilter '(objectCategory=computer)' $Identity $LDAPFilter $Filter
        if ($Identity) {
            $r = @(ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                    -SearchBase $SearchBase -SearchScope $SearchScope `
                    -Properties $Properties -Filter $f `
                    -DefaultProps $script:ADSI_DefaultProperties.Computer `
                    -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADComputer')
            if ($r.Count -eq 0) { throw "オブジェクトが見つかりません (Identity='$Identity')" }
            $r
        }
        else {
            ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                -SearchBase $SearchBase -SearchScope $SearchScope `
                -Properties $Properties -Filter $f `
                -DefaultProps $script:ADSI_DefaultProperties.Computer `
                -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADComputer'
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADComputer に失敗しました' }
}

function Get-ADOrganizationalUnit {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [string[]]$Properties,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )

    try {
        $f = ADSI_BuildFinalFilter '(objectCategory=organizationalUnit)' $Identity $LDAPFilter $Filter
        if ($Identity) {
            $r = @(ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                    -SearchBase $SearchBase -Properties $Properties -Filter $f `
                    -DefaultProps $script:ADSI_DefaultProperties.OU `
                    -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADOrganizationalUnit')
            if ($r.Count -eq 0) { throw "オブジェクトが見つかりません (Identity='$Identity')" }
            $r
        }
        else {
            ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                -SearchBase $SearchBase -Properties $Properties -Filter $f `
                -DefaultProps $script:ADSI_DefaultProperties.OU `
                -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADOrganizationalUnit'
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADOrganizationalUnit に失敗しました' }
}

function Get-ADObject {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [switch]$IncludeDeletedObjects,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [string[]]$Properties,
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )

    try {
        $f = ADSI_BuildFinalFilter '(objectClass=*)' $Identity $LDAPFilter $Filter
        if ($Identity) {
            $r = @(ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                    -SearchBase $SearchBase -Properties $Properties -Filter $f `
                    -DefaultProps $script:ADSI_DefaultProperties.Object `
                    -Tombstone:$IncludeDeletedObjects `
                    -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADObject')
            if ($r.Count -eq 0) { throw "オブジェクトが見つかりません (Identity='$Identity')" }
            $r
        }
        else {
            ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                -SearchBase $SearchBase -Properties $Properties -Filter $f `
                -DefaultProps $script:ADSI_DefaultProperties.Object `
                -Tombstone:$IncludeDeletedObjects `
                -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADObject'
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADObject に失敗しました' }
}

function Get-ADGroupMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Identity,

        [switch]$Recursive,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$ResultSetSize = 0,   # 0 = 無制限。>0 で件数上限（超過時は警告）
        [int]$Timeout = 0          # 0 = 無制限。>0 で全体タイムアウト秒
    )

    try {
        # 対象グループを特定（DN を得る）
        $g = Get-ADGroup -Identity $Identity -Server $Server -UseSSL:$UseSSL `
                -Credential $Credential -SearchBase $SearchBase |
             Select-Object -First 1
        if (-not $g) { throw "グループが見つかりません: $Identity" }

        $nc   = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $base = if ($SearchBase) { $SearchBase } else { $nc.Default }

        # 解決用の接続を1本だけ張って使い回す（負荷低減）
        $conn = New-ADSConnection -Server $Server -UseSSL:$UseSSL -Credential $Credential -Path $base
        try {
            $sw       = [System.Diagnostics.Stopwatch]::StartNew()
            $emitted  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $count    = 0
            $aborted  = $false

            if (-not $Recursive) {
                # --- 直接メンバーのみ（range 取得で1500件超も取りこぼさない） ---
                $dns  = ADSI_GetMemberDNsRanged -Conn $conn -GroupDN $g.DistinguishedName -ClientTimeoutSec $Timeout
                $objs = ADSI_ResolveDNObjects -Conn $conn -DNs $dns -ClientTimeoutSec $Timeout

                # Domain Users 等は member 属性が空のため、primaryGroupID 経由のメンバーも連結する
                $primaryObjs = ADSI_GetPrimaryGroupMembers -Conn $conn -GroupSid $g.SID -ClientTimeoutSec $Timeout -MaxResults $ResultSetSize
                $seenDn = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                $allObjs = New-Object System.Collections.Generic.List[object]
                foreach ($o in $objs)        { if ($seenDn.Add($o.DistinguishedName)) { $allObjs.Add($o) } }
                foreach ($o in $primaryObjs) { if ($seenDn.Add($o.DistinguishedName)) { $allObjs.Add($o) } }

                # member DN 解決の取りこぼし検出（primary 分を除いた差分でチェック）
                if ($dns.Count -ne $objs.Count) {
                    Write-Warning "メンバー $($dns.Count - $objs.Count) 件が検索ベース配下で解決できませんでした（他ドメイン/ForeignSecurityPrincipal の可能性）"
                }

                foreach ($o in $allObjs) {
                    if ($ResultSetSize -gt 0 -and $count -ge $ResultSetSize) {
                        Write-Warning "結果が上限 $ResultSetSize 件に達したため打ち切りました（-ResultSetSize で変更可）。"
                        break
                    }
                    $o | Select-Object DistinguishedName, Name, SamAccountName, ObjectClass, SID
                    $count++
                }
                return
            }

            # --- 再帰展開（循環検出・重複排除・進捗・上限・タイムアウト） ---
            $visited = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $queue   = New-Object System.Collections.Generic.Queue[object]
            $queue.Enqueue([pscustomobject]@{ DN = $g.DistinguishedName; Name = $g.Name; Sid = $g.SID })

            while ($queue.Count -gt 0) {
                if ($Timeout -gt 0 -and $sw.Elapsed.TotalSeconds -gt $Timeout) {
                    Write-Warning "処理時間が $Timeout 秒を超えたため打ち切りました（-Timeout で変更可）。"
                    $aborted = $true
                    break
                }

                $cur = $queue.Dequeue()
                if (-not $visited.Add($cur.DN)) { continue }   # 既展開（循環）はスキップ

                Write-Progress -Activity "Get-ADGroupMember -Recursive" `
                    -Status "展開中: $($cur.Name) / 取得 $count 件 / 残りグループ $($queue.Count)"

                $dns  = ADSI_GetMemberDNsRanged -Conn $conn -GroupDN $cur.DN -ClientTimeoutSec $Timeout
                $objs = ADSI_ResolveDNObjects -Conn $conn -DNs $dns -ClientTimeoutSec $Timeout

                # member DN 解決の取りこぼし検出（primary 分を除いた差分でチェック）
                if ($dns.Count -ne $objs.Count) {
                    Write-Warning "メンバー $($dns.Count - $objs.Count) 件が検索ベース配下で解決できませんでした（他ドメイン/ForeignSecurityPrincipal の可能性）"
                }

                # Domain Users 等は member 属性が空のため、primaryGroupID 経由のメンバーも連結する
                $primaryObjs = ADSI_GetPrimaryGroupMembers -Conn $conn -GroupSid $cur.Sid -ClientTimeoutSec $Timeout -MaxResults $ResultSetSize
                $objs = @($objs) + @($primaryObjs)

                foreach ($o in $objs) {
                    if ($o.IsGroup) {
                        # ネストグループは出力せず展開対象に積む（RSAT -Recursive と同挙動）
                        if (-not $visited.Contains($o.DistinguishedName)) {
                            $queue.Enqueue([pscustomobject]@{ DN = $o.DistinguishedName; Name = $o.Name; Sid = $o.SID })
                        }
                        continue
                    }

                    # 葉メンバー（ユーザー/コンピュータ等）のみ、重複排除して出力
                    if ($emitted.Add($o.DistinguishedName)) {
                        if ($ResultSetSize -gt 0 -and $count -ge $ResultSetSize) {
                            Write-Warning "結果が上限 $ResultSetSize 件に達したため打ち切りました（-ResultSetSize で変更可）。"
                            $aborted = $true
                            break
                        }
                        $o | Select-Object DistinguishedName, Name, SamAccountName, ObjectClass, SID
                        $count++
                    }
                }

                if ($aborted) { break }
            }

            Write-Progress -Activity "Get-ADGroupMember -Recursive" -Completed
        }
        finally { $conn.Dispose() }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADGroupMember に失敗しました' }
}

function Get-ADServiceAccount {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$LDAPFilter,
        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential,
        [string]$SearchBase,
        [string[]]$Properties,
        [ValidateSet('Base','OneLevel','Subtree')]
        [string]$SearchScope = 'Subtree',
        [int]$ResultSetSize = 0,
        [int]$Timeout = 0
    )

    try {
        $f = ADSI_BuildFinalFilter '(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))' $Identity $LDAPFilter $Filter
        if ($Identity) {
            $r = @(ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                    -SearchBase $SearchBase -SearchScope $SearchScope -Properties $Properties -Filter $f `
                    -DefaultProps $script:ADSI_DefaultProperties.ServiceAccount `
                    -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADServiceAccount')
            if ($r.Count -eq 0) { throw "オブジェクトが見つかりません (Identity='$Identity')" }
            $r
        }
        else {
            ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                -SearchBase $SearchBase -SearchScope $SearchScope -Properties $Properties -Filter $f `
                -DefaultProps $script:ADSI_DefaultProperties.ServiceAccount `
                -ResultSetSize $ResultSetSize -TimeoutSeconds $Timeout -ProgressActivity 'Get-ADServiceAccount'
        }
    }
    catch { ADSI_ThrowLdap $_ 'Get-ADServiceAccount に失敗しました' }
}

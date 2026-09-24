function Get-ADGpoLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Target,

        [string]$Server,
        [switch]$UseSSL,
        [pscredential]$Credential
    )

    try {
        $ou = Get-ADOrganizationalUnit -Identity $Target `
                -Server $Server -UseSSL:$UseSSL -Credential $Credential `
                -Properties gPLink |
              Select-Object -First 1

        if (-not $ou -or [string]::IsNullOrWhiteSpace([string]$ou.gPLink)) {
            return
        }

        $gPLink = [string]$ou.gPLink

        # gPLink 形式: [LDAP://CN={GUID},...;flag][...]  ※LDAP:// は通常大文字だが念のため (?i)
        $matches_ = [regex]::Matches($gPLink, '(?i)\[LDAP://CN=(\{[^}]+\})[^;]*;(\d+)\]')
        if ($matches_.Count -eq 0) { return }

        # GPO 名解決: CN=Policies,CN=System,<defaultNamingContext>
        $nc      = ADSI_GetNamingContexts -Server $Server -UseSSL:$UseSSL -Credential $Credential
        $polBase = "CN=Policies,CN=System,$($nc.Default)"

        $gpos = ADSI_Query -Server $Server -UseSSL:$UseSSL -Credential $Credential `
            -SearchBase $polBase `
            -Filter '(objectClass=groupPolicyContainer)' `
            -DefaultProps @('Name','DisplayName','ObjectGUID')

        # GUID (大文字) → DisplayName のマップ
        $gpoMap = @{}
        foreach ($g in $gpos) {
            if ($g.Name) {
                $gpoMap[$g.Name.ToUpperInvariant()] = $g.DisplayName
            }
        }

        $order = 1
        foreach ($m in $matches_) {
            $guid     = $m.Groups[1].Value
            $flag     = [int]$m.Groups[2].Value

            # フラグはビット演算
            # bit0 = 1: リンク無効  bit1 = 2: 適用強制
            $enabled  = -not [bool]($flag -band 1)
            $enforced = [bool]($flag -band 2)

            $gpoName = $gpoMap[$guid.ToUpperInvariant()]
            if (-not $gpoName) { $gpoName = $guid }

            [pscustomobject]@{
                TargetOU    = $Target
                GpoName     = $gpoName
                GpoGuid     = $guid
                LinkEnabled = $enabled
                Enforced    = $enforced
                Order       = $order
            }

            $order++
        }
    }
    catch {
        ADSI_ThrowLdap $_ 'Get-ADGpoLink に失敗しました'
    }
}

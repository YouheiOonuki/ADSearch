function ADSI_EscapeLdapValue {
    param([string]$v)

    if ($null -eq $v) { return $v }

    return $v.
        Replace('\','\5c').
        Replace('*','\2a').
        Replace('(','\28').
        Replace(')','\29').
        Replace("`0",'\00')
}

function ADSI_EscapeLdapLike {
    param([string]$v)

    if ($null -eq $v) { return $v }

    return $v.
        Replace('\','\5c').
        Replace('(','\28').
        Replace(')','\29')
}

function ADSI_GuidToLdapFilter {
    param([guid]$g)

    return (($g.ToByteArray() | ForEach-Object {
        '\' + ('{0:x2}' -f $_)
    }) -join '')
}

function ADSI_SidToLdapFilter {
    param([string]$Sid)

    $s = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $b = New-Object byte[] $s.BinaryLength
    $s.GetBinaryForm($b, 0)

    return (($b | ForEach-Object {
        '\' + ('{0:x2}' -f $_)
    }) -join '')
}

function ADSI_FilterAttr {
    param([string]$Name)

    $k = $Name.ToLowerInvariant()

    if ($script:ADSI_FilterAlias.ContainsKey($k)) {
        return $script:ADSI_FilterAlias[$k]
    }

    return $Name
}

function ADSI_WrapFilter {
    param([string]$f)

    if ([string]::IsNullOrWhiteSpace($f)) {
        return $f
    }

    $x = $f.Trim()

    if ($x.StartsWith('(')) {
        return $x
    }

    return "($x)"
}

function ADSI_AndFilters {
    param(
        [string]$a,
        [string]$b
    )

    if ([string]::IsNullOrWhiteSpace($a)) { return $b }
    if ([string]::IsNullOrWhiteSpace($b)) { return $a }

    return "(&$(ADSI_WrapFilter $a)$(ADSI_WrapFilter $b))"
}

# -Filter で日時プロパティ（FileTime 属性）として扱うプロパティ名 → LDAP 属性名
$script:ADSI_FiletimeFilterProps = @{
    lastlogondate          = 'lastLogonTimestamp'
    passwordlastset        = 'pwdLastSet'
    accountexpirationdate  = 'accountExpires'
    lastbadpasswordattempt = 'badPasswordTime'
    accountlockouttime     = 'lockoutTime'
}

# -Filter で Generalized-Time 属性として扱うプロパティ名 → LDAP 属性名
$script:ADSI_GeneralizedTimeFilterProps = @{
    created  = 'whenCreated'
    modified = 'whenChanged'
}

# -Filter で userAccountControl ビットプロパティとして扱うプロパティ名 → ビット値
$script:ADSI_UacBitFilterProps = @{
    passwordneverexpires   = 0x10000
    passwordnotrequired    = 0x20
    smartcardlogonrequired = 0x40000
    trustedfordelegation   = 0x80000
}

# -Filter でサーバー側フィルター不可（構築属性/クライアント計算値）なプロパティ名
# 注: enabled は既存特別扱いがあるためここには含めない
$script:ADSI_NonFilterableProps = @(
    'lockedout','passwordexpired','passwordexpirydate','machinepasswordage',
    'ipv4address','ipv6address','linkedgrouppolicyobjects'
)

# -Filter の日時リテラルを culture 非依存でパースする。
# ISO 8601 系の明示フォーマットのみ受理し、端末ロケール差による誤解釈を防ぐ。
# タイムゾーン指定のない値はローカル時刻として扱う（RSAT と同じ挙動）。
function ADSI_ParseFilterDate([string]$s) {
    $formats = [string[]]@(
        'yyyy-MM-dd',
        'yyyy-MM-ddTHH:mm:ss',
        'yyyy-MM-dd HH:mm:ss',
        'yyyy-MM-dd HH:mm',
        'yyyy/MM/dd',
        'yyyy/MM/dd HH:mm:ss',
        'yyyy/MM/dd HH:mm'
    )
    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    $styles = [System.Globalization.DateTimeStyles]::AssumeLocal
    $dt = [datetime]::MinValue
    if ([datetime]::TryParseExact($s, $formats, $ci, $styles, [ref]$dt)) {
        return $dt
    }
    throw "'$s' を日時として解釈できません（対応形式: yyyy-MM-dd[ HH:mm[:ss]] / yyyy/MM/dd[ HH:mm[:ss]]）"
}

function ADSI_ConvertComparison {
    param([string]$Clause)

    $c = $Clause.Trim()

    while ($c.StartsWith('(') -and $c.EndsWith(')')) {
        $c = $c.Substring(1, $c.Length - 2).Trim()
    }

    if ($c -notmatch '^(.+?)\s+-(eq|ne|like|notlike|ge|le|gt|lt|approx)\s+(.+)$') {
        throw "未対応の -Filter 句: $Clause"
    }

    $left  = $matches[1].Trim()
    $op    = $matches[2].ToLowerInvariant()
    $right = $matches[3].Trim()

    if ($right -ieq '$true') {
        $right = 'TRUE'
    }
    elseif ($right -ieq '$false') {
        $right = 'FALSE'
    }
    elseif (
        ($right.StartsWith("'") -and $right.EndsWith("'")) -or
        ($right.StartsWith('"') -and $right.EndsWith('"'))
    ) {
        $right = $right.Substring(1, $right.Length - 2)
    }

    $leftKey = $left.ToLowerInvariant()

    # サーバー側フィルター不可能プロパティ（構築属性/クライアント計算値）は明確に throw
    if ($script:ADSI_NonFilterableProps -contains $leftKey) {
        throw "プロパティ '$left' は構築属性/クライアント計算値のためサーバー側フィルター不可です。取得後に Where-Object で絞り込んでください"
    }

    # 日時プロパティ（FileTime 属性）
    if ($script:ADSI_FiletimeFilterProps.ContainsKey($leftKey)) {
        if ($op -notin @('eq','ne','ge','le','gt','lt')) {
            throw "日時プロパティ '$left' に -$op は使用できません"
        }
        $ldapAttr = $script:ADSI_FiletimeFilterProps[$leftKey]
        $ft = $null
        $tmp = 0L
        if ([int64]::TryParse($right, [ref]$tmp)) {
            $ft = $tmp
        }
        else {
            $ft = (ADSI_ParseFilterDate $right).ToFileTime()
        }
        switch ($op) {
            'eq' { return "($ldapAttr=$ft)" }
            'ne' { return "(!($ldapAttr=$ft))" }
            'ge' { return "($ldapAttr>=$ft)" }
            'le' { return "($ldapAttr<=$ft)" }
            'gt' { return "(!($ldapAttr<=$ft))" }
            'lt' { return "(!($ldapAttr>=$ft))" }
        }
    }

    # Created / Modified（Generalized-Time 属性）
    if ($script:ADSI_GeneralizedTimeFilterProps.ContainsKey($leftKey)) {
        if ($op -notin @('eq','ne','ge','le','gt','lt')) {
            throw "日時プロパティ '$left' に -$op は使用できません"
        }
        $ldapAttr = $script:ADSI_GeneralizedTimeFilterProps[$leftKey]
        $gt = (ADSI_ParseFilterDate $right).ToUniversalTime().ToString('yyyyMMddHHmmss.0\Z')
        switch ($op) {
            'eq' { return "($ldapAttr=$gt)" }
            'ne' { return "(!($ldapAttr=$gt))" }
            'ge' { return "($ldapAttr>=$gt)" }
            'le' { return "($ldapAttr<=$gt)" }
            'gt' { return "(!($ldapAttr<=$gt))" }
            'lt' { return "(!($ldapAttr>=$gt))" }
        }
    }

    # userAccountControl ビットプロパティ
    if ($script:ADSI_UacBitFilterProps.ContainsKey($leftKey)) {
        if ($op -notin @('eq','ne')) {
            throw "プロパティ '$left' に -$op は使用できません"
        }
        $bit = $script:ADSI_UacBitFilterProps[$leftKey]
        if (($op -eq 'eq' -and $right -ieq 'TRUE') -or ($op -eq 'ne' -and $right -ieq 'FALSE')) {
            return "(userAccountControl:1.2.840.113556.1.4.803:=$bit)"
        }
        if (($op -eq 'eq' -and $right -ieq 'FALSE') -or ($op -eq 'ne' -and $right -ieq 'TRUE')) {
            return "(!(userAccountControl:1.2.840.113556.1.4.803:=$bit))"
        }
    }

    $attr = ADSI_FilterAttr $left

    if ($left -ieq 'Enabled') {
        if (($op -eq 'eq' -and $right -ieq 'TRUE') -or ($op -eq 'ne' -and $right -ieq 'FALSE')) {
            return '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        }

        if (($op -eq 'eq' -and $right -ieq 'FALSE') -or ($op -eq 'ne' -and $right -ieq 'TRUE')) {
            return '(userAccountControl:1.2.840.113556.1.4.803:=2)'
        }
    }

    switch ($op) {
        'eq'      { return "($attr=$(ADSI_EscapeLdapValue $right))" }
        'ne'      { return "(!($attr=$(ADSI_EscapeLdapValue $right)))" }
        'like'    { return "($attr=$(ADSI_EscapeLdapLike $right))" }
        'notlike' { return "(!($attr=$(ADSI_EscapeLdapLike $right)))" }
        'ge'      { return "($attr>=$(ADSI_EscapeLdapValue $right))" }
        'le'      { return "($attr<=$(ADSI_EscapeLdapValue $right))" }
        'gt'      { return "(!($attr<=$(ADSI_EscapeLdapValue $right)))" }
        'lt'      { return "(!($attr>=$(ADSI_EscapeLdapValue $right)))" }
        'approx'  { return "($attr~=$(ADSI_EscapeLdapValue $right))" }
    }
}

# ------------------------------------------------------------
# PowerShell 風 -Filter のパーサ（再帰下降）
#   orExpr  := andExpr ( -or  andExpr )*
#   andExpr := term    ( -and term    )*
#   term    := '(' orExpr ')' | comparison
# 括弧によるグループ化と -and/-or の任意ネスト・混在に対応。
# クォート内の文字は構造解析の対象外。
# ------------------------------------------------------------

function ADSI_TokenizeFilter {
    param([string]$s)

    $tokens = New-Object System.Collections.Generic.List[hashtable]
    $buf    = New-Object System.Text.StringBuilder
    $i      = 0
    $q      = $null

    $flush = {
        $t = $buf.ToString().Trim()
        if ($t) { [void]$tokens.Add(@{ T = 'COMP'; V = $t }) }
        [void]$buf.Clear()
    }

    while ($i -lt $s.Length) {
        $ch = $s[$i]

        if ($q) {
            [void]$buf.Append($ch)
            if ($ch -eq $q) { $q = $null }
            $i++
            continue
        }

        if ($ch -eq "'" -or $ch -eq '"') {
            $q = $ch
            [void]$buf.Append($ch)
            $i++
            continue
        }

        $rest = $s.Substring($i)

        $mAnd = [regex]::Match($rest, '^\s+-and(\s+|$)', 'IgnoreCase')
        if ($mAnd.Success) {
            & $flush
            [void]$tokens.Add(@{ T = 'AND' })
            $i += $mAnd.Length
            continue
        }

        $mOr = [regex]::Match($rest, '^\s+-or(\s+|$)', 'IgnoreCase')
        if ($mOr.Success) {
            & $flush
            [void]$tokens.Add(@{ T = 'OR' })
            $i += $mOr.Length
            continue
        }

        if ($ch -eq '(') {
            & $flush
            [void]$tokens.Add(@{ T = 'LP' })
            $i++
            continue
        }

        if ($ch -eq ')') {
            & $flush
            [void]$tokens.Add(@{ T = 'RP' })
            $i++
            continue
        }

        [void]$buf.Append($ch)
        $i++
    }

    & $flush
    return ,$tokens
}

function ADSI_ParseOr {
    param($Tokens, [ref]$Pos)
    $items = @(ADSI_ParseAnd $Tokens $Pos)
    while ($Pos.Value -lt $Tokens.Count -and $Tokens[$Pos.Value].T -eq 'OR') {
        $Pos.Value++
        $items += ADSI_ParseAnd $Tokens $Pos
    }
    if ($items.Count -eq 1) { return $items[0] }
    return "(|$($items -join ''))"
}

function ADSI_ParseAnd {
    param($Tokens, [ref]$Pos)
    $items = @(ADSI_ParseTerm $Tokens $Pos)
    while ($Pos.Value -lt $Tokens.Count -and $Tokens[$Pos.Value].T -eq 'AND') {
        $Pos.Value++
        $items += ADSI_ParseTerm $Tokens $Pos
    }
    if ($items.Count -eq 1) { return $items[0] }
    return "(&$($items -join ''))"
}

function ADSI_ParseTerm {
    param($Tokens, [ref]$Pos)

    if ($Pos.Value -ge $Tokens.Count) { throw '-Filter 式が不完全です' }

    $tok = $Tokens[$Pos.Value]

    if ($tok.T -eq 'LP') {
        $Pos.Value++
        $inner = ADSI_ParseOr $Tokens $Pos
        if ($Pos.Value -ge $Tokens.Count -or $Tokens[$Pos.Value].T -ne 'RP') {
            throw '-Filter の括弧が閉じていません'
        }
        $Pos.Value++
        return $inner
    }

    if ($tok.T -eq 'COMP') {
        $Pos.Value++
        return ADSI_ConvertComparison $tok.V
    }

    throw "-Filter で予期しないトークンです: $($tok.T)"
}

function ADSI_PsFilterToLdap {
    param([string]$Expr)

    if ([string]::IsNullOrWhiteSpace($Expr) -or $Expr.Trim() -eq '*') {
        return '(objectClass=*)'
    }

    $e = $Expr.Trim()

    # PowerShell 演算子を含まない場合は生の LDAP フィルターとみなして素通し
    if ($e -notmatch '(?i)\s-(eq|ne|like|notlike|ge|le|gt|lt|approx|and|or)\b') {
        if ($e.StartsWith('(')) { return $e }
        throw "解釈できない -Filter 式です: $Expr （生の LDAP は -LDAPFilter を使用してください）"
    }

    $tokens = ADSI_TokenizeFilter $e
    if ($tokens.Count -eq 0) { return '(objectClass=*)' }

    $pos  = [ref]0
    $ldap = ADSI_ParseOr $tokens $pos

    if ($pos.Value -ne $tokens.Count) {
        throw "-Filter 式を解釈しきれませんでした: $Expr"
    }

    return $ldap
}

function ADSI_ConvertFilterToLDAP {
    param(
        [string]$Filter,
        [string]$ObjectFilter
    )

    if ([string]::IsNullOrWhiteSpace($Filter) -or $Filter.Trim() -eq '*') {
        return $ObjectFilter
    }

    return ADSI_AndFilters $ObjectFilter (ADSI_PsFilterToLdap $Filter)
}

function ADSI_ResolveIdentityFilter {
    param([string]$Identity)

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        return $null
    }

    $id = $Identity.Trim()

    if ($id -match '^(?i)(CN|OU|DC)=') {
        return "(distinguishedName=$(ADSI_EscapeLdapValue $id))"
    }

    $g = [guid]::Empty

    if ([guid]::TryParse($id, [ref]$g)) {
        return "(objectGUID=$(ADSI_GuidToLdapFilter $g))"
    }

    if ($id -match '^S-1-') {
        try {
            return "(objectSid=$(ADSI_SidToLdapFilter $id))"
        }
        catch {}
    }

    # RSAT の -Identity は DN / GUID / SID / sAMAccountName のみ受理。cn/name/UPN/mail での
    # 曖昧一致は誤オブジェクト取得防止のため廃止（旧: @ を含む場合の UPN/mail 分岐、cn/name フォールバック）。
    $e = ADSI_EscapeLdapValue $id
    return "(sAMAccountName=$e)"
}

function ADSI_BuildFinalFilter {
    param(
        [string]$ObjectFilter,
        [string]$Identity,
        [string]$LDAPFilter,
        [string]$Filter
    )

    if ($Identity) {
        return ADSI_AndFilters $ObjectFilter (ADSI_ResolveIdentityFilter $Identity)
    }

    if ($LDAPFilter) {
        return ADSI_AndFilters $ObjectFilter $LDAPFilter
    }

    if ($Filter) {
        return ADSI_ConvertFilterToLDAP $Filter $ObjectFilter
    }

    return $ObjectFilter
}

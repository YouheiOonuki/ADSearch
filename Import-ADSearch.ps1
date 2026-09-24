<#
.SYNOPSIS
    実行ポリシー（RemoteSigned 等）に阻まれる環境でも ADSearch を読み込むローダー
.DESCRIPTION
    ネットワーク共有（UNC）上の .ps1/.psm1 は RemoteSigned 環境では署名が必要で
    そのままでは読み込めない。本ローダーは各ファイルを「文字列として読み込み
    ScriptBlock 化してドットソース」することで、ファイル実行ポリシーのチェックを
    受けずに関数を現在のセッションへ取り込む。

    使い方（共有上から）:
        # ① ローダー自身も ScriptBlock 化して取り込む（1回だけ）
        . ([scriptblock]::Create((Get-Content '\\server\tools\ADSearch\Import-ADSearch.ps1' -Raw)))
        # ② フォルダを指定して読み込む
        Import-ADSearch -Path '\\server\tools\ADSearch'

    ローカルにコピー済みなら通常どおり . .\ADSearch.ps1 でも可。
#>
function Import-ADSearch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # ADSearch.ps1 / ADSearch.psm1 のドットソース順と一致させること（新ファイル追加時は3箇所更新）
    $order = @(
        'ADSearch.Core.ps1',
        'ADSearch.Filters.ps1',
        'ADSearch.Objects.ps1',
        'ADSearch.Directory.ps1',
        'ADSearch.Gpo.ps1',
        'ADSearch.Dns.ps1',
        'ADSearch.Exchange.ps1',
        'ADSearch.ExchangeRecipients.ps1',
        'ADSearch.Diagnostics.ps1',
        'ADSearch.SelfTest.ps1'
    )

    foreach ($name in $order) {
        $file = Join-Path $Path $name
        if (-not (Test-Path -LiteralPath $file)) {
            throw "ファイルが見つかりません: $file"
        }
        $code = Get-Content -LiteralPath $file -Raw
        # 関数内で . ([scriptblock]) するとドットソース先が関数スコープになり、
        # 取り込んだ関数が Import-ADSearch の終了とともに失われる。
        # 各関数定義を global: に書き換えてグローバルスコープへ確実に取り込む。
        $code = $code -replace '(?m)^function\s+([\w-]+)', 'function global:$1'
        . ([scriptblock]::Create($code))
    }

    Write-Host "ADSearch を読み込みました ($Path)"
}

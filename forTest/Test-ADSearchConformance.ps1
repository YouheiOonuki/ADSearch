# Test-ADSearchConformance.ps1
#
# Purpose:
#   Standing conformance gate for the ADSearch module. Runs anywhere with NO
#   domain controller required. Detects:
#     - export registration gaps (psd1 FunctionsToExport vs actual module
#       exports vs function definitions)
#     - documentation drift (Reference HTML / README mention functions that
#       are not actually exported)
#     - missing comment-based help (Synopsis)
#     - optionally (with -DryInvoke) whether each public function reaches its
#       query-construction stage before failing at the connection layer
#
# Usage:
#   powershell -File forTest\Test-ADSearchConformance.ps1
#   powershell -File forTest\Test-ADSearchConformance.ps1 -DryInvoke
#
# Exit code: 0 if all checks pass, 1 if any check fails.

param(
    [switch]$DryInvoke
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent

$rows = New-Object System.Collections.Generic.List[object]

function Add-ConformanceRow {
    param(
        [string]$Check,
        [string]$Result,
        [string]$Detail
    )

    $rows.Add([pscustomobject]@{
        Check  = $Check
        Result = $Result
        Detail = $Detail
    })
}

function Add-ConformanceRowConditional {
    param(
        [string]$Check,
        [bool]$Passed,
        [string]$PassDetail,
        [string]$FailDetail
    )

    if ($Passed) {
        Add-ConformanceRow $Check 'Pass' $PassDetail
    }
    else {
        Add-ConformanceRow $Check 'Fail' $FailDetail
    }
}

# ------------------------------------------------------------------
# 1. Manifest import (real path)
# ------------------------------------------------------------------
$psd1Path = Join-Path $repoRoot 'ADSearch.psd1'
$importOk = $true
try {
    Import-Module $psd1Path -Force -ErrorAction Stop
    Add-ConformanceRow 'Manifest import (real path)' 'Pass' "Imported: $psd1Path"
}
catch {
    $importOk = $false
    Add-ConformanceRow 'Manifest import (real path)' 'Fail' $_.Exception.Message
}

if (-not $importOk) {
    "`n==== Conformance Results ===="
    $rows | Format-Table Check, Result, Detail -AutoSize -Wrap
    "`nFAIL count: 1 (fatal: module import failed)"
    exit 1
}

# ------------------------------------------------------------------
# 2. Export parity
# ------------------------------------------------------------------
$declared = @((Import-PowerShellDataFile $psd1Path).FunctionsToExport)
$mod = Get-Module ADSearch
$effective = @($mod.ExportedCommands.Keys)

$notExported = @($declared | Where-Object { $effective -notcontains $_ })
$extraExported = @($effective | Where-Object { $declared -notcontains $_ })

if ($notExported.Count -eq 0 -and $extraExported.Count -eq 0) {
    Add-ConformanceRow 'Export parity (psd1 vs ExportedCommands)' 'Pass' "$($declared.Count) functions match"
}
else {
    $detail = @()
    if ($notExported.Count -gt 0) { $detail += 'declared but not exported: ' + ($notExported -join ', ') }
    if ($extraExported.Count -gt 0) { $detail += 'exported but not declared: ' + ($extraExported -join ', ') }
    Add-ConformanceRow 'Export parity (psd1 vs ExportedCommands)' 'Fail' ($detail -join ' / ')
}

$unresolved = @(
    $declared | Where-Object {
        -not (Get-Command $_ -Module ADSearch -ErrorAction SilentlyContinue)
    }
)

Add-ConformanceRowConditional 'Export parity (declared functions resolve)' `
    ($unresolved.Count -eq 0) `
    "$($declared.Count) declared functions resolve via Get-Command -Module ADSearch" `
    ('unresolved: ' + ($unresolved -join ', '))

# ------------------------------------------------------------------
# 3. Doc parity
# ------------------------------------------------------------------
$refPath = Join-Path $repoRoot 'ADSearch_Reference.html'
if (Test-Path -LiteralPath $refPath) {
    $refText = Get-Content -LiteralPath $refPath -Raw
    $idMatches = [regex]::Matches($refText, 'id="((?:Get|Search|Invoke)-[A-Za-z]+)"')
    $refIds = @($idMatches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)

    $refMissing = @($refIds | Where-Object { $effective -notcontains $_ })

    Add-ConformanceRowConditional 'Doc parity (Reference HTML ids)' `
        ($refMissing.Count -eq 0) `
        "$($refIds.Count) function ids checked, all exported" `
        ('ids in HTML but not exported: ' + ($refMissing -join ', '))
}
else {
    Add-ConformanceRow 'Doc parity (Reference HTML ids)' 'Fail' "Reference HTML not found: $refPath"
}

$readmePath = Join-Path $repoRoot 'README.md'
if (Test-Path -LiteralPath $readmePath) {
    $readmeText = Get-Content -LiteralPath $readmePath -Raw
    $tokenMatches = [regex]::Matches($readmeText, '\b(Get|Search|Invoke)-[A-Za-z]+')
    $readmeTokens = @($tokenMatches | ForEach-Object { $_.Value } | Sort-Object -Unique)

    $allowList = @('Get-Content', 'Get-Command', 'Get-Module', 'Get-Help', 'Get-Date', 'Get-ChildItem')
    $readmeTokens = @($readmeTokens | Where-Object { $allowList -notcontains $_ })

    $readmeMissing = @($readmeTokens | Where-Object { $effective -notcontains $_ })

    Add-ConformanceRowConditional 'Doc parity (README tokens)' `
        ($readmeMissing.Count -eq 0) `
        "$($readmeTokens.Count) function tokens checked, all exported" `
        ('tokens in README but not exported: ' + ($readmeMissing -join ', '))
}
else {
    Add-ConformanceRow 'Doc parity (README tokens)' 'Fail' "README not found: $readmePath"
}

# ------------------------------------------------------------------
# 4. Help presence
# ------------------------------------------------------------------
$noHelp = @()
foreach ($name in $effective) {
    $help = Get-Help $name -ErrorAction SilentlyContinue
    if (-not $help -or [string]::IsNullOrWhiteSpace([string]$help.Synopsis)) {
        $noHelp += $name
    }
}

Add-ConformanceRowConditional 'Help presence (Synopsis)' `
    ($noHelp.Count -eq 0) `
    "$($effective.Count) functions have non-empty Synopsis" `
    ('missing Synopsis: ' + ($noHelp -join ', '))

# ------------------------------------------------------------------
# 5. Bounded dry-invoke (opt-in via -DryInvoke)
# ------------------------------------------------------------------
if ($DryInvoke) {

    $dummyParamsByFunction = @{
        'Get-ADGroupMember'           = @{ Identity = 'dummy' }
        'Get-ADUserHealth'            = @{ Identity = 'dummy' }
        'Get-ADComputerHealth'        = @{ Identity = 'dummy' }
        'Get-DistributionGroupMember' = @{ Identity = 'dummy' }
        'Get-ADDnsRecord'             = @{ ZoneName = 'example.local' }
        'Search-ADAccount'            = @{ AccountDisabled = $true }
    }

    $dryJob = Start-Job -ArgumentList $repoRoot, $effective, $dummyParamsByFunction -ScriptBlock {
        param($repoRoot, $effective, $dummyParamsByFunction)

        Import-Module (Join-Path $repoRoot 'ADSearch.psd1') -Force

        $jobResults = New-Object System.Collections.Generic.List[object]

        foreach ($name in $effective) {
            $cmd = Get-Command $name -Module ADSearch -ErrorAction SilentlyContinue
            if (-not $cmd) { continue }

            $params = @{}
            $paramNames = $cmd.Parameters.Keys

            if ($paramNames -contains 'Server') { $params.Server = '127.0.0.1' }
            elseif ($paramNames -contains 'ComputerName') { $params.ComputerName = '127.0.0.1' }

            if ($paramNames -contains 'Timeout') { $params.Timeout = 3 }

            if ($dummyParamsByFunction.ContainsKey($name)) {
                foreach ($k in $dummyParamsByFunction[$name].Keys) {
                    if ($paramNames -contains $k) {
                        $params[$k] = $dummyParamsByFunction[$name][$k]
                    }
                }
            }

            # Safety net: fill in ANY remaining mandatory parameter with a
            # dummy value so a job never blocks on an interactive mandatory-
            # parameter prompt (which would deadlock Wait-Job).
            # Commands with a single parameter set are safe to auto-fill:
            # any mandatory parameter there is unconditionally required
            # (e.g. Get-ADGpoLink's -Target). Commands with multiple
            # parameter sets (e.g. Search-ADAccount's mutually exclusive
            # -LockedOut / -AccountDisabled / -AccountExpired / ...) are
            # NOT auto-filled here, because filling more than one mandatory
            # switch from different sets makes the parameter set ambiguous
            # and PowerShell throws ParameterBindingException. Those cases
            # must be covered explicitly via $dummyParamsByFunction.
            if ($cmd.ParameterSets.Count -eq 1) {
                foreach ($p in $cmd.Parameters.Values) {
                    if ($params.ContainsKey($p.Name)) { continue }
                    $isMandatory = $false
                    foreach ($pset in $p.ParameterSets.Values) {
                        if ($pset.IsMandatory) { $isMandatory = $true }
                    }
                    if (-not $isMandatory) { continue }

                    if ($p.ParameterType -eq [switch]) {
                        $params[$p.Name] = $true
                    }
                    else {
                        $params[$p.Name] = 'dummy'
                    }
                }
            }

            try {
                & $name @params 2>&1 | Out-Null
                $jobResults.Add([pscustomobject]@{
                    Name   = $name
                    Result = 'Pass'
                    Detail = 'no exception (unexpected but acceptable)'
                })
            }
            catch [System.Management.Automation.ParameterBindingException] {
                $jobResults.Add([pscustomobject]@{
                    Name   = $name
                    Result = 'Fail'
                    Detail = 'ParameterBindingException: ' + $_.Exception.Message
                })
            }
            catch {
                $jobResults.Add([pscustomobject]@{
                    Name   = $name
                    Result = 'Pass'
                    Detail = $_.Exception.GetType().Name + ': reached beyond parameter binding'
                })
            }
        }

        return $jobResults
    }

    $completed = Wait-Job -Job $dryJob -Timeout 120

    if (-not $completed) {
        Stop-Job -Job $dryJob -ErrorAction SilentlyContinue
        Add-ConformanceRow 'Bounded dry-invoke' 'Warn' 'Timed out after 120s; ADSI bind can hang and ignore -Timeout. No functions judged.'
    }
    else {
        $jobOutput = Receive-Job -Job $dryJob
        $dryFail = @($jobOutput | Where-Object { $_.Result -eq 'Fail' })

        if ($dryFail.Count -eq 0) {
            Add-ConformanceRow 'Bounded dry-invoke' 'Pass' "$(@($jobOutput).Count) functions dry-invoked, none failed at ParameterBindingException"
        }
        else {
            $detail = ($dryFail | ForEach-Object { "$($_.Name): $($_.Detail)" }) -join ' | '
            Add-ConformanceRow 'Bounded dry-invoke' 'Fail' $detail
        }
    }

    Remove-Job -Job $dryJob -Force -ErrorAction SilentlyContinue
}
else {
    # 実行しなかったものを Pass と書かない。2026-08-02 まで 'Pass' だったため、
    # -DryInvoke が既定 off の通常実行では「7項目すべて Pass・exit 0」と出て、
    # この検査が一度も走っていないことが結果から読み取れなかった。
    Add-ConformanceRow 'Bounded dry-invoke' 'Skip' '(not run; pass -DryInvoke to enable)'
}

# ------------------------------------------------------------------
# 6. Summary
# ------------------------------------------------------------------
"`n==== Conformance Results ===="
$rows | Format-Table Check, Result, Detail -AutoSize -Wrap

$failCount = @($rows | Where-Object { $_.Result -eq 'Fail' }).Count
$warnCount = @($rows | Where-Object { $_.Result -eq 'Warn' }).Count
$skipCount = @($rows | Where-Object { $_.Result -eq 'Skip' }).Count
$passCount = @($rows | Where-Object { $_.Result -eq 'Pass' }).Count

# 母数を必ず出す。Pass の件数だけでは「何項目中いくつか」が読めない。
"`nChecks: $($rows.Count)  Pass: $passCount  Fail: $failCount  Warn: $warnCount  Skip: $skipCount"

# Warn を成功に数えない。Warn が付くのは dry-invoke が 120 秒で打ち切られた
# ときで、その本文は 'No functions judged.' と書いている。**判定していないと
# 知りながら成功で終える**のは、検査が対象を検査していないのと同じ
# （estate-audit 03 の型H）。
if ($failCount -gt 0 -or $warnCount -gt 0) {
    if ($warnCount -gt 0 -and $failCount -eq 0) {
        "判定できなかった項目があるため失敗として扱う（Warn: $warnCount）。"
    }
    exit 1
}

# Skip は失敗にしない。走らせない選択は正当だが、結果表に Skip として
# 残るので「全部通った」とは読めない。
if ($skipCount -gt 0) { "未実行の項目が $skipCount 件ある（-DryInvoke で有効化）。" }
exit 0

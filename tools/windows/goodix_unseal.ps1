# SPDX-License-Identifier: LGPL-2.1-or-later
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SealedBlob,

    [Parameter(Mandatory = $true)]
    [string]$OutPsk,

    [ValidateSet('LocalService', 'System')]
    [string]$Account = 'LocalService'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell prompt.'
}

$sealedPath = [IO.Path]::GetFullPath($SealedBlob)
$outputPath = [IO.Path]::GetFullPath($OutPsk)
if (-not [IO.File]::Exists($sealedPath)) {
    throw "Sealed blob not found: $sealedPath"
}
if ([IO.File]::Exists($outputPath)) {
    throw "Output already exists: $outputPath"
}

$blob = [IO.File]::ReadAllBytes($sealedPath)
$expectedHeader = [byte[]](
    0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf,
    0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0
)
if ($blob.Length -ne 324) {
    throw "Sealed blob must contain exactly 324 bytes, got $($blob.Length)."
}
for ($i = 0; $i -lt $expectedHeader.Length; $i++) {
    if ($blob[$i] -ne $expectedHeader[$i]) {
        throw 'Sealed blob does not have the canonical DPAPI header.'
    }
}
[Array]::Clear($blob, 0, $blob.Length)

$accountId = if ($Account -eq 'LocalService') {
    'S-1-5-19'
} else {
    'S-1-5-18'
}
$accountName = if ($Account -eq 'LocalService') {
    'LOCAL SERVICE'
} else {
    'SYSTEM'
}

$workRoot = Join-Path $env:ProgramData 'libfprint-goodix-55b4'
$workPath = Join-Path $workRoot ([Guid]::NewGuid().ToString('N'))
$stagedBlob = Join-Path $workPath 'sealed.bin'
$stagedPsk = Join-Path $workPath 'psk.bin'
$stagedError = Join-Path $workPath 'error.txt'
$stagedDone = Join-Path $workPath 'done'
$payloadPath = Join-Path $workPath 'unseal-payload.ps1'
$taskName = 'Goodix55b4Unseal-' + [Guid]::NewGuid().ToString('N')
$taskCreated = $false
$plain = $null

try {
    New-Item -ItemType Directory -Path $workPath -Force | Out-Null
    & icacls.exe $workPath /inheritance:r /grant:r `
        '*S-1-5-18:(OI)(CI)F' `
        '*S-1-5-19:(OI)(CI)F' `
        '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not protect the temporary directory ACL.'
    }
    Copy-Item -LiteralPath $sealedPath -Destination $stagedBlob

    $payload = @'
param([string]$InputPath, [string]$OutputPath, [string]$ErrorPath, [string]$DonePath)
$ErrorActionPreference = 'Stop'
$sealed = $null
$plain = $null
try {
    Add-Type -AssemblyName System.Security
    $sealed = [IO.File]::ReadAllBytes($InputPath)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $sealed,
        $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser)
    if ($plain.Length -ne 32) {
        throw "DPAPI returned $($plain.Length) bytes instead of 32."
    }
    [IO.File]::WriteAllBytes($OutputPath, $plain)
    [IO.File]::WriteAllText($DonePath, 'complete')
} catch {
    [IO.File]::WriteAllText($ErrorPath, $_.Exception.Message)
    exit 1
} finally {
    if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($null -ne $sealed) { [Array]::Clear($sealed, 0, $sealed.Length) }
}
'@
    Set-Content -LiteralPath $payloadPath -Value $payload -Encoding Ascii

    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
        "-File `"$payloadPath`" " +
        "-InputPath `"$stagedBlob`" " +
        "-OutputPath `"$stagedPsk`" " +
        "-ErrorPath `"$stagedError`" " +
        "-DonePath `"$stagedDone`""
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument $arguments
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $accountId `
        -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action `
        -Principal $taskPrincipal | Out-Null
    $taskCreated = $true
    Start-ScheduledTask -TaskName $taskName

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not [IO.File]::Exists($stagedDone) -and
           -not [IO.File]::Exists($stagedError) -and
           [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }

    if ([IO.File]::Exists($stagedError)) {
        $failure = [IO.File]::ReadAllText($stagedError)
        throw "DPAPI failed under $accountName. $failure"
    }
    if (-not [IO.File]::Exists($stagedDone)) {
        throw "The $accountName task did not produce output within 30 seconds."
    }

    $plain = [IO.File]::ReadAllBytes($stagedPsk)
    if ($plain.Length -ne 32) {
        throw "Unsealed key must contain exactly 32 bytes, got $($plain.Length)."
    }

    $outputDirectory = [IO.Path]::GetDirectoryName($outputPath)
    if (-not [IO.Directory]::Exists($outputDirectory)) {
        throw "Output directory does not exist: $outputDirectory"
    }
    $temporaryOutput = Join-Path $outputDirectory `
        ('.goodix-psk-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $stream = [IO.FileStream]::new(
            $temporaryOutput,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        $stream.Dispose()

        $fileAcl = Get-Acl -LiteralPath $temporaryOutput
        $fileAcl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($fileAcl.Access)) {
            [void]$fileAcl.RemoveAccessRuleSpecific($rule)
        }
        $rights = [Security.AccessControl.FileSystemRights]::FullControl
        $allow = [Security.AccessControl.AccessControlType]::Allow
        $fileAcl.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $identity.User, $rights, $allow))
        $fileAcl.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
                $rights,
                $allow))
        Set-Acl -LiteralPath $temporaryOutput -AclObject $fileAcl

        $stream = [IO.FileStream]::new(
            $temporaryOutput,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $stream.Write($plain, 0, $plain.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        [IO.File]::Move($temporaryOutput, $outputPath)
    } finally {
        if ([IO.File]::Exists($temporaryOutput)) {
            Remove-Item -LiteralPath $temporaryOutput -Force
        }
        [Array]::Clear($plain, 0, $plain.Length)
    }

    Write-Host "PSK saved to a private 32-byte file: $outputPath"
} finally {
    if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($taskCreated) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Warning 'Temporary unseal task cleanup failed; remove the task before leaving this machine.'
    }
    if ([IO.Directory]::Exists($workPath)) {
        Remove-Item -LiteralPath $workPath -Recurse -Force `
            -ErrorAction SilentlyContinue
        if ([IO.Directory]::Exists($workPath)) {
            Write-Warning 'Temporary unseal directory cleanup failed; remove it before leaving this machine.'
        }
    }
}

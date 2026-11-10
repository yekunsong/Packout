# Corpus construction helper (SPEC §9). Called by gen on Windows only.
#
# Exit codes are part of the generator contract:
#   0  ok
#   2  privilege missing (symlink without developer mode / elevation)
#   3  capability unsupported (no fsutil, FS without sparse / case sensitivity, attr rejected)
#   4  Win32 ate the literal name (trailing dot / space / reserved name)
#   1  other error
#
# Every path handed in is already absolute. Callers that need the literal Win32
# form prefix it with \\?\ themselves.
param(
    [Parameter(Mandatory = $true)][string]$Action,
    [string]$Path,
    [string]$Target,
    [string]$Expect,
    [string]$Name,
    [string]$Value,
    [long]$Size = 0
)

$ErrorActionPreference = 'Stop'

function Fail([int]$code, [string]$msg) {
    [Console]::Error.WriteLine($msg)
    exit $code
}
function Priv($msg) { Fail 2 $msg }
function Unsup($msg) { Fail 3 $msg }
function IsPrivError([string]$msg) {
    return ($msg -match 'privilege|elevation|管理员|权限|拒绝访问|Access is denied')
}

$CorpusAttr = $null
function AddNative {
    if ($script:CorpusAttr -ne $null) { return }
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class CorpusAttr {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool SetFileInformationByHandle(
    SafeFileHandle h, int cls, byte[] info, uint len);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern uint GetFinalPathNameByHandle(
    SafeFileHandle h, StringBuilder buf, uint len, uint flags);
}
"@
    $script:CorpusAttr = $true
}

function RunCmd([string]$line) {
    # Native stderr becomes an ErrorRecord under 'Stop'; keep going and use
    # $LASTEXITCODE, otherwise every expected failure would abort the script.
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = cmd.exe /c $line 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    return @{ code = $code; out = $out.Trim() }
}

switch ($Action) {
    'junction' {
        $r = RunCmd ('mklink /J "{0}" "{1}"' -f $Path, $Target)
        if ($r.code -ne 0) {
            if (IsPrivError $r.out) { Priv $r.out } else { Fail 1 $r.out }
        }
    }
    'symlink-dir' {
        $r = RunCmd ('mklink /D "{0}" "{1}"' -f $Path, $Target)
        if ($r.code -ne 0) {
            if (IsPrivError $r.out) { Priv $r.out } else { Fail 1 $r.out }
        }
    }
    'symlink-file' {
        $r = RunCmd ('mklink "{0}" "{1}"' -f $Path, $Target)
        if ($r.code -ne 0) {
            if (IsPrivError $r.out) { Priv $r.out } else { Fail 1 $r.out }
        }
    }
    'hardlink' {
        $r = RunCmd ('mklink /H "{0}" "{1}"' -f $Path, $Target)
        if ($r.code -ne 0) {
            if (IsPrivError $r.out) { Priv $r.out } else { Fail 1 $r.out }
        }
    }
    'literal-file' {
        # [IO.File]::Create honours \\?\ (SPEC §9.3).
        $bytes = @()
        if ($Value) { $bytes = [Convert]::FromBase64String($Value) }
        try {
            $fs = [IO.File]::Create($Path)
            try { if ($bytes.Length -gt 0) { $fs.Write($bytes, 0, $bytes.Length) } }
            finally { $fs.Dispose() }
        } catch {
            $msg = $_.Exception.Message
            if (IsPrivError $msg) { Priv $msg } else { Fail 1 $msg }
        }
        if ($Expect) {
            # Verify the on-disk name through the handle, not through path parsing.
            AddNative
            $final = ''
            try {
                $probe = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
                try {
                    $sb = New-Object System.Text.StringBuilder 32768
                    $n = [CorpusAttr]::GetFinalPathNameByHandle($probe.SafeFileHandle, $sb, 32768, 0)
                    $final = $sb.ToString(0, [int]$n)
                } finally { $probe.Dispose() }
            } catch {
                Fail 1 $_.Exception.Message
            }
            $final = $final -replace '^\\\\\?\\', ''
            if (-not $final.EndsWith($Expect, [StringComparison]::Ordinal)) {
                Fail 4 "name eaten: expected suffix [$Expect], got [$final]"
            }
        }
    }
    'mkdir-literal' {
        try { [void][IO.Directory]::CreateDirectory($Path) }
        catch {
            $msg = $_.Exception.Message
            if (IsPrivError $msg) { Priv $msg } else { Fail 1 $msg }
        }
    }
    'shortname' {
        $r = RunCmd ('fsutil file setShortName "{0}" "{1}"' -f $Path, $Name)
        if ($r.code -ne 0) { Unsup $r.out }
    }
    'sparse' {
        if (-not (Get-Command fsutil.exe -ErrorAction SilentlyContinue)) { Unsup 'fsutil missing' }
        $r = RunCmd ('fsutil file createnew "{0}" {1}' -f $Path, $Size)
        if ($r.code -ne 0) {
            if (IsPrivError $r.out) { Unsup $r.out } else { Fail 1 $r.out }
        }
        $r = RunCmd ('fsutil sparse setflag "{0}"' -f $Path)
        if ($r.code -ne 0) {
            if (IsPrivError $r.out) { Unsup $r.out } else { Fail 1 $r.out }
        }
        $r = RunCmd ('fsutil sparse setzerodata offset=0 length={0} "{1}"' -f $Size, $Path)
        if ($r.code -ne 0) {
            if (IsPrivError $r.out) { Unsup $r.out } else { Fail 1 $r.out }
        }
    }
    'recall' {
        AddNative
        $attrs = [uint32]0x00401000   # OFFLINE | RECALL_ON_DATA_ACCESS
        try {
            $fs = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
            try {
                $bi = New-Object byte[] 40    # FILE_BASIC_INFO
                [BitConverter]::GetBytes($attrs).CopyTo($bi, 32)
                if (-not [CorpusAttr]::SetFileInformationByHandle($fs.SafeFileHandle, 0, $bi, 40)) {
                    throw ('SetFileInformationByHandle failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
                }
            } finally { $fs.Dispose() }
        } catch {
            Unsup $_.Exception.Message
        }
        $got = (Get-Item -LiteralPath $Path -Force).Attributes
        if (-not (($got -band [IO.FileAttributes]::Offline) -or ($got -band [IO.FileAttributes]::RecallOnDataAccess))) {
            Unsup "recall attributes did not stick: $got"
        }
    }
    'readonly' {
        $r = RunCmd ('attrib +R "{0}"' -f $Path)
        if ($r.code -ne 0) { Fail 1 $r.out }
    }
    'ads' {
        try {
            if ($Value) { Set-Content -LiteralPath $Path -Stream $Name -Value $Value -NoNewline -Encoding ascii }
            else { Set-Content -LiteralPath $Path -Stream $Name -Value '' -NoNewline -Encoding ascii }
        } catch {
            Unsup $_.Exception.Message
        }
    }
    'case-sensitive' {
        $r = RunCmd ('fsutil file setCaseSensitiveInfo "{0}" enable' -f $Path)
        if ($r.code -ne 0) {
            if (IsPrivError $r.out) { Unsup $r.out } else { Fail 1 $r.out }
        }
    }
    default { Fail 1 "unknown action: $Action" }
}

exit 0

#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Materialize the packout selftest fixtures, including objects that cannot be
  stored in git.

.DESCRIPTION
  Reads each built-in profile (profiles/<name>.jsonc), copies the external
  fixture tree bound by selftest.fixtures into a build tree, and materializes
  the zero-filled files and empty directories declared by selftest.files /
  selftest.dirs. Those selftest declarations are the single source of truth;
  generated.json only lists objects that text files cannot express.

  OS-specific "special" objects (symlinks, Windows junctions, sparse files and
  the NTFS offline placeholder attribute) come from generated.json and are
  created only in the build tree.

  The source fixture tree is never modified. Every individual creation step is
  best-effort: an unsupported or unprivileged operation is reported as SKIP,
  and the script still exits 0. This is deliberate, because symlink, junction,
  sparse and placeholder support varies by OS, filesystem and privilege.

  The special objects are for manual verification/probing only. They are not
  referenced by the profiles' selftest blocks; see README.md.

.EXAMPLE
  pwsh -NoProfile -File tools/make-fixtures.ps1

.EXAMPLE
  pwsh -NoProfile -File tools/make-fixtures.ps1 -OutDir C:\temp\packout-fixtures -Clean
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [switch]$Clean,
    [switch]$NoSpecial
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$fixturesRoot = Split-Path -Parent $scriptDir
$profilesRoot = Split-Path -Parent $fixturesRoot
$manifestPath = Join-Path $fixturesRoot 'generated.json'

if (-not $OutDir) {
    $OutDir = Join-Path $fixturesRoot 'build'
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir)

# $IsWindows only exists on PowerShell 6+; fall back to the environment marker.
$onWindows = $true
if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
    $onWindows = [bool]$IsWindows
} else {
    $onWindows = ($env:OS -eq 'Windows_NT')
}

$script:created = 0
$script:skipped = 0
$script:skips = New-Object System.Collections.Generic.List[string]

function Write-Ok([string]$message) {
    $script:created++
    Write-Host ("OK    " + $message)
}

function Write-Skip([string]$message) {
    $script:skipped++
    $script:skips.Add($message)
    Write-Host ("SKIP  " + $message)
}

function Ensure-Parent([string]$path) {
    $parent = Split-Path -Parent $path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
}

function New-ZeroFile([string]$path, [int]$size) {
    if (Test-Path -LiteralPath $path) {
        Write-Skip "file already exists: $path"
        return
    }
    Ensure-Parent $path
    [System.IO.File]::WriteAllBytes($path, [byte[]]::new($size))
    Write-Ok "file $path ($size bytes, zero-filled)"
}

function New-TextFile([string]$path, [string]$content) {
    if (Test-Path -LiteralPath $path) {
        Write-Skip "file already exists: $path"
        return
    }
    Ensure-Parent $path
    [System.IO.File]::WriteAllText($path, $content)
    Write-Ok "file $path (text)"
}

function New-EmptyDir([string]$path) {
    if (Test-Path -LiteralPath $path) {
        Write-Skip "directory already exists: $path"
        return
    }
    New-Item -ItemType Directory -Force -Path $path | Out-Null
    Write-Ok "dir  $path"
}

function New-Link([string]$path, [string]$target, [bool]$junction) {
    if (Test-Path -LiteralPath $path) {
        Write-Skip "link already exists: $path"
        return
    }
    Ensure-Parent $path
    $absoluteTarget = $target
    if (-not [System.IO.Path]::IsPathRooted($target)) {
        $absoluteTarget = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $path) $target))
    }

    try {
        if ($junction -and $onWindows) {
            New-Item -ItemType Junction -Path $path -Target $absoluteTarget -ErrorAction Stop | Out-Null
        } else {
            New-Item -ItemType SymbolicLink -Path $path -Target $absoluteTarget -ErrorAction Stop | Out-Null
        }
        Write-Ok ("link {0} -> {1} ({2})" -f $path, $absoluteTarget, $(if ($junction) { 'junction' } else { 'symlink' }))
        return
    } catch {
        # Fall through to cmd.exe mklink; it sometimes succeeds where
        # New-Item refuses (and never needs PowerShell's symlink checks).
        if ($onWindows) {
            try {
                $flag = if ($junction) { '/J' } else { '/D' }
                & cmd.exe /c mklink $flag $path $absoluteTarget | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Ok "link $path -> $absoluteTarget (via mklink)"
                    return
                }
            } catch {
                # Reported below.
            }
        }
        Write-Skip ("cannot create {0} at {1} (needs privilege/dev mode/filesystem support)" -f $(if ($junction) { 'junction' } else { 'symlink' }), $path)
    }
}

function Set-SparseFile([string]$path, [int]$size) {
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Skip "sparse target missing: $path"
        return
    }
    try {
        if ($onWindows) {
            & fsutil.exe sparse setflag $path | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "fsutil sparse setflag failed" }
            & fsutil.exe sparse setrange $path 0 $size | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "fsutil sparse setrange failed" }
        } else {
            & truncate -s $size $path
            if ($LASTEXITCODE -ne 0) { throw "truncate failed" }
        }
        Write-Ok "sparse $path ($size bytes)"
    } catch {
        Write-Skip "cannot mark sparse: $path (needs NTFS/admin or sparse-capable filesystem)"
    }
}

function Set-OfflinePlaceholder([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Skip "placeholder target missing: $path"
        return
    }
    if (-not $onWindows) {
        Write-Skip "offline placeholder attribute is NTFS-only: $path"
        return
    }
    try {
        & attrib.exe +O $path | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "attrib +O failed" }
        Write-Ok "offline placeholder attribute on $path"
    } catch {
        Write-Skip "cannot set offline placeholder attribute: $path"
    }
}

function Get-PropertyValue($object, [string]$name) {
    if ($null -eq $object) { return $null }
    $property = $object.PSObject.Properties[$name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

# Strip // and /* */ comments plus trailing commas from JSONC without touching
# string literals. Profiles are JSONC (hujson); ConvertFrom-Json is strict JSON.
function ConvertFrom-Jsonc([string]$text) {
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    $n = $text.Length
    $inString = $false
    $escaped = $false
    while ($i -lt $n) {
        $c = $text[$i]
        if ($inString) {
            [void]$sb.Append($c)
            if ($escaped) {
                $escaped = $false
            } elseif ($c -eq '\') {
                $escaped = $true
            } elseif ($c -eq '"') {
                $inString = $false
            }
            $i++
            continue
        }
        if ($c -eq '"') {
            $inString = $true
            [void]$sb.Append($c)
            $i++
            continue
        }
        if ($c -eq '/' -and ($i + 1) -lt $n -and $text[$i + 1] -eq '/') {
            while (($i -lt $n) -and ($text[$i] -ne "`n")) { $i++ }
            continue
        }
        if ($c -eq '/' -and ($i + 1) -lt $n -and $text[$i + 1] -eq '*') {
            $i += 2
            while (($i + 1) -lt $n -and -not ($text[$i] -eq '*' -and $text[$i + 1] -eq '/')) { $i++ }
            $i += 2
            continue
        }
        [void]$sb.Append($c)
        $i++
    }

    # Second pass: drop commas that only precede } or ] (outside strings).
    $src = $sb.ToString()
    $out = New-Object System.Text.StringBuilder
    $inString = $false
    $escaped = $false
    for ($j = 0; $j -lt $src.Length; $j++) {
        $c = $src[$j]
        if ($inString) {
            [void]$out.Append($c)
            if ($escaped) { $escaped = $false }
            elseif ($c -eq '\') { $escaped = $true }
            elseif ($c -eq '"') { $inString = $false }
            continue
        }
        if ($c -eq '"') { $inString = $true; [void]$out.Append($c); continue }
        if ($c -eq ',') {
            $k = $j + 1
            while ($k -lt $src.Length -and [char]::IsWhiteSpace($src[$k])) { $k++ }
            if ($k -lt $src.Length -and ($src[$k] -eq '}' -or $src[$k] -eq ']')) { continue }
        }
        [void]$out.Append($c)
    }
    return ($out.ToString() | ConvertFrom-Json)
}

function Invoke-SpecialSection($profileName, $instances) {
    foreach ($instanceProperty in $instances.PSObject.Properties) {
        if ($instanceProperty.Name -eq 'comment') { continue }
        $instanceName = $instanceProperty.Name
        $spec = $instanceProperty.Value
        $instanceDir = Join-Path (Join-Path $OutDir $profileName) $instanceName

        if (-not (Test-Path -LiteralPath $instanceDir)) {
            Write-Skip "instance tree missing: $instanceDir"
            continue
        }

        foreach ($dir in @(Get-PropertyValue $spec 'dirs')) {
            if ($null -eq $dir) { continue }
            New-EmptyDir (Join-Path $instanceDir ([string]$dir))
        }
        foreach ($file in @(Get-PropertyValue $spec 'files')) {
            if ($null -eq $file) { continue }
            $path = Join-Path $instanceDir ([string]$file.path)
            $content = Get-PropertyValue $file 'content'
            if ($null -ne $content) {
                New-TextFile $path ([string]$content)
            } else {
                New-ZeroFile $path ([int]$file.size)
            }
        }
        foreach ($link in @(Get-PropertyValue $spec 'symlinks')) {
            if ($null -eq $link) { continue }
            New-Link (Join-Path $instanceDir ([string]$link.path)) ([string]$link.target) $false
        }
        foreach ($junction in @(Get-PropertyValue $spec 'junctions')) {
            if ($null -eq $junction) { continue }
            New-Link (Join-Path $instanceDir ([string]$junction.path)) ([string]$junction.target) $true
        }
        foreach ($sparse in @(Get-PropertyValue $spec 'sparse')) {
            if ($null -eq $sparse) { continue }
            Set-SparseFile (Join-Path $instanceDir ([string]$sparse.path)) ([int]$sparse.size)
        }
        foreach ($placeholder in @(Get-PropertyValue $spec 'placeholder')) {
            if ($null -eq $placeholder) { continue }
            Set-OfflinePlaceholder (Join-Path $instanceDir ([string]$placeholder.path))
        }
    }
}

function Resolve-InstancePath([string]$rootDir, $instanceRoots, [string]$relative) {
    $normalized = $relative -replace '\\', '/'
    $parts = $normalized.Split('/')
    if ($parts.Length -lt 2) { return $null }
    $instance = $parts[0]
    if (-not $instanceRoots.ContainsKey($instance)) {
        Write-Skip "selftest path references unbound instance '$instance': $relative"
        return $null
    }
    $tail = ($parts[1..($parts.Length - 1)] -join [System.IO.Path]::DirectorySeparatorChar)
    return (Join-Path $instanceRoots[$instance] $tail)
}

$manifest = $null
if (Test-Path -LiteralPath $manifestPath) {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
} else {
    Write-Skip "manifest not found: $manifestPath"
}

if ($Clean -and (Test-Path -LiteralPath $OutDir)) {
    try {
        Remove-Item -LiteralPath $OutDir -Recurse -Force
    } catch {
        Write-Skip "cannot clean $OutDir"
    }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 1. For every built-in profile, copy the external fixtures bound by
#    selftest.fixtures, then materialize selftest.files / selftest.dirs.
$profileFiles = @()
if (Test-Path -LiteralPath $profilesRoot) {
    $profileFiles = @(Get-ChildItem -LiteralPath $profilesRoot -Filter '*.jsonc' -File | Sort-Object Name)
}
if ($profileFiles.Count -eq 0) {
    Write-Skip "no profiles/<name>.jsonc found; nothing to materialize"
}

foreach ($profileFile in $profileFiles) {
    $profileName = [System.IO.Path]::GetFileNameWithoutExtension($profileFile.Name)
    try {
        $profile = ConvertFrom-Jsonc (Get-Content -LiteralPath $profileFile.FullName -Raw)
    } catch {
        Write-Skip "cannot parse profile: $($profileFile.FullName)"
        continue
    }

    $selftest = Get-PropertyValue $profile 'selftest'
    $fixtures = Get-PropertyValue $selftest 'fixtures'
    if ($null -eq $fixtures) {
        Write-Skip "profile has no selftest.fixtures: $profileName"
        continue
    }

    $instanceRoots = @{}
    foreach ($fixtureProperty in $fixtures.PSObject.Properties) {
        $instanceName = $fixtureProperty.Name
        $sourceRelative = [string]$fixtureProperty.Value
        $source = Join-Path $profilesRoot ($sourceRelative -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        $destination = Join-Path (Join-Path $OutDir $profileName) $instanceName
        $instanceRoots[$instanceName] = $destination
        if (-not (Test-Path -LiteralPath $source)) {
            Write-Skip "fixture source missing: $source"
            continue
        }
        try {
            if (Test-Path -LiteralPath $destination) {
                Remove-Item -LiteralPath $destination -Recurse -Force
            }
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
            Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force
            Write-Ok "copied $source -> $destination"
        } catch {
            Write-Skip "cannot copy $source"
        }
    }

    foreach ($dir in @(Get-PropertyValue $selftest 'dirs')) {
        if ($null -eq $dir) { continue }
        $path = Resolve-InstancePath $profilesRoot $instanceRoots ([string]$dir)
        if ($path) { New-EmptyDir $path }
    }
    foreach ($file in @(Get-PropertyValue $selftest 'files')) {
        if ($null -eq $file) { continue }
        $path = Resolve-InstancePath $profilesRoot $instanceRoots ([string]$file.path)
        if (-not $path) { continue }
        $content = Get-PropertyValue $file 'content'
        if ($null -ne $content) {
            New-TextFile $path ([string]$content)
        } else {
            New-ZeroFile $path ([int]$file.size)
        }
    }
    foreach ($link in @(Get-PropertyValue $selftest 'symlinks')) {
        if ($null -eq $link) { continue }
        $path = Resolve-InstancePath $profilesRoot $instanceRoots ([string]$link.path)
        if ($path) { New-Link $path ([string]$link.target) $false }
    }
}

# 2. Add OS-specific objects that cannot live in git.
if (-not $NoSpecial -and $null -ne $manifest) {
    $specialSection = Get-PropertyValue $manifest 'special'
    if ($null -ne $specialSection) {
        foreach ($profileProperty in $specialSection.PSObject.Properties) {
            if ($profileProperty.Name -eq 'comment') { continue }
            Invoke-SpecialSection $profileProperty.Name $profileProperty.Value
        }
    }
}

Write-Host ""
Write-Host ("Fixtures materialized in {0}" -f $OutDir)
Write-Host ("  created: {0}   skipped: {1}" -f $script:created, $script:skipped)
if ($script:skips.Count -gt 0) {
    Write-Host "Skipped items (non-fatal):"
    foreach ($skip in $script:skips) {
        Write-Host ("  - " + $skip)
    }
}

# A skipped object is never an error for this script: platforms differ.
exit 0

#Requires -Version 7
# Copy this working tree into a public companion clone.
# Default target: <repo>/../K2F-Purge
# Includes .github/workflows/release.yml. Excludes agent/Trellis dirs and build output.
param(
    [Parameter(Position = 0)]
    [string]$Target = '',
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# git non-zero (e.g. "not a repo") must not throw; we inspect $LASTEXITCODE.
$PSNativeCommandUseErrorActionPreference = $false

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

if ([string]::IsNullOrWhiteSpace($Target)) {
    $Target = Join-Path (Split-Path -Parent $RepoRoot) 'K2F-Purge'
}

if (-not [System.IO.Path]::IsPathRooted($Target)) {
    $Target = Join-Path (Get-Location) $Target
}
$Target = [System.IO.Path]::GetFullPath($Target)

function Test-GitRepo([string]$Path) {
    # Root of a clone (dir) or worktree (file). A subdirectory of some other
    # repo is not a git repo of its own — git -C would still succeed there.
    $gitDir = Join-Path $Path '.git'
    return (Test-Path -LiteralPath $gitDir)
}

function Test-DirEmpty([string]$Path) {
    $entries = @(Get-ChildItem -LiteralPath $Path -Force)
    return ($entries.Count -eq 0)
}

$SkipTop = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($name in @(
        '.git', '.trellis', '.claude', '.agents', '.grok', '.pi',
        'build', '.mygo', 'dist', 'quarantine'
    )) {
    [void]$SkipTop.Add($name)
}

function Test-ShouldSkip([string]$Rel) {
    $n = $Rel.Replace('\', '/')
    if ([string]::IsNullOrWhiteSpace($n)) {
        return $true
    }
    $parts = $n.Split('/')
    if ($SkipTop.Contains($parts[0])) {
        return $true
    }
    $base = $parts[-1]
    if ($base -eq '.DS_Store' -or $base -eq 'Thumbs.db') {
        return $true
    }
    if ($base.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    # The public repo has no Trellis; its contributor guide is README.md.
    if ($n -eq 'AGENTS.md') {
        return $true
    }
    # The AstrLink Guard model is downloaded at build time and must never
    # land in the public companion repo (about 37 MiB of binaries).
    if ($n -ieq 'resources/astrlink-guard' -or
        $n.StartsWith('resources/astrlink-guard/', [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    # locales/catalog_gen.go is generated but tracked: the public repo's CI
    # runs `go test ./...` before any mygo build regenerates it.
    return $false
}

if (Test-Path -LiteralPath $Target) {
    if (-not (Test-Path -LiteralPath $Target -PathType Container)) {
        throw "error: target exists and is not a directory: $Target"
    }
    if (-not (Test-GitRepo $Target) -and -not (Test-DirEmpty $Target)) {
        throw "error: target is not empty and not a git repo: $Target"
    }
}

$listed = @(& git -C $RepoRoot ls-files -co --exclude-standard)
if ($LASTEXITCODE -ne 0) {
    throw "git ls-files failed in $RepoRoot (exit $LASTEXITCODE)"
}

$copied = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$copyCount = 0

if ($DryRun) {
    Write-Output "dry-run: $RepoRoot -> $Target"
}

foreach ($rel in $listed) {
    if ([string]::IsNullOrWhiteSpace($rel)) {
        continue
    }
    $norm = $rel.Replace('\', '/')
    if (Test-ShouldSkip $norm) {
        continue
    }
    $src = Join-Path $RepoRoot ($norm.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    if (-not (Test-Path -LiteralPath $src)) {
        continue
    }
    [void]$copied.Add($norm)
    $copyCount++
    if ($DryRun) {
        Write-Output $norm
        continue
    }
    $dest = Join-Path $Target ($norm.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $destDir = Split-Path -Parent $dest
    if (-not (Test-Path -LiteralPath $destDir)) {
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    }
    Copy-Item -LiteralPath $src -Destination $dest -Force
}

# Mirror rsync --delete, but never touch .git or excluded agent/build trees.
if (Test-Path -LiteralPath $Target -PathType Container) {
    Get-ChildItem -LiteralPath $Target -Recurse -Force -File | ForEach-Object {
        $full = [System.IO.Path]::GetFullPath($_.FullName)
        $root = $Target.TrimEnd('\', '/')
        if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
            return
        }
        $rel = $full.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
        if (Test-ShouldSkip $rel) {
            return
        }
        if ($copied.Contains($rel)) {
            return
        }
        if ($DryRun) {
            Write-Output "delete $rel"
        }
        else {
            Remove-Item -LiteralPath $_.FullName -Force
        }
    }

    if (-not $DryRun) {
        Get-ChildItem -LiteralPath $Target -Recurse -Force -Directory |
            Sort-Object { $_.FullName.Length } -Descending |
            ForEach-Object {
                $full = [System.IO.Path]::GetFullPath($_.FullName)
                $root = $Target.TrimEnd('\', '/')
                if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                    return
                }
                $rel = $full.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
                if (Test-ShouldSkip $rel) {
                    return
                }
                $children = @(Get-ChildItem -LiteralPath $_.FullName -Force)
                if ($children.Count -eq 0) {
                    Remove-Item -LiteralPath $_.FullName -Force
                }
            }
    }
}

if (-not $DryRun) {
    Write-Output "copied $copyCount files -> $Target"
}

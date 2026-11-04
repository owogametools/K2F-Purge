#Requires -Version 7
# Download and verify the AstrLink Guard model files used by release builds.
# The model is not tracked in git. Run this before `go tool mygo build` when
# packaging a release; valid existing files are skipped, so re-running is safe.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$Revision = '7216b6a3b897ef903d4b1ba367ae6fb95b0fa5e4'
$Revision12 = $Revision.Substring(0, 12)
$Dest = Join-Path $RepoRoot "resources/astrlink-guard/$Revision12"
$Base = "https://huggingface.co/QuantumNous/astrlink-guard/resolve/$Revision"

$Files = @(
    [pscustomobject]@{
        Remote = 'int8/model_int8.onnx'
        Name   = 'model_int8.onnx'
        Size   = 330781
        Sha256 = '0a070d3113615e33ba3b84d6bd486f663a377c04c4b056e7381732179f51832a'
    }
    [pscustomobject]@{
        Remote = 'int8/model_int8.onnx_data'
        Name   = 'model_int8.onnx_data'
        Size   = 37124608
        Sha256 = '0ba34216ceead01e0ae2dfd8e46d52b67e7aee80b04f722d9b758613a91c0067'
    }
    [pscustomobject]@{
        Remote = 'int8/tokenizer.json'
        Name   = 'tokenizer.json'
        Size   = 1502881
        Sha256 = '0cf3b235ef125658015a6c8026a5fe6f28088bf825101a990ec18a10200feef4'
    }
)

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-ModelFile([string]$Path, [long]$Size, [string]$Sha256) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne $Size) {
        return $false
    }
    return ((Get-Sha256 $Path) -eq $Sha256)
}

New-Item -ItemType Directory -Force -Path $Dest | Out-Null

foreach ($file in $Files) {
    $out = Join-Path $Dest $file.Name

    if (Test-ModelFile $out $file.Size $file.Sha256) {
        Write-Output "ok      $($file.Name)"
        continue
    }
    if (Test-Path -LiteralPath $out) {
        Write-Output "invalid $($file.Name) (size or sha256 mismatch); re-downloading"
    }

    $tmp = "$out.part"
    try {
        Write-Output "fetch   $($file.Name)"
        Invoke-WebRequest -Uri "$Base/$($file.Remote)" -OutFile $tmp
        $gotSize = (Get-Item -LiteralPath $tmp).Length
        if ($gotSize -ne $file.Size) {
            throw "$($file.Name) size mismatch: expected $($file.Size), got $gotSize"
        }
        $gotSha = Get-Sha256 $tmp
        if ($gotSha -ne $file.Sha256) {
            throw "$($file.Name) sha256 mismatch: expected $($file.Sha256), got $gotSha"
        }
        Move-Item -LiteralPath $tmp -Destination $out -Force
        Write-Output "verified $($file.Name)"
    }
    catch {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw
    }
}

Write-Output "AstrLink model ready: $Dest"

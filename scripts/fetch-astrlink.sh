#!/bin/sh
# Download and verify the AstrLink Guard model files used by release builds.
# The model is not tracked in git. Run this before `go tool mygo build` when
# packaging a release; valid existing files are skipped, so re-running is safe.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rev=7216b6a3b897ef903d4b1ba367ae6fb95b0fa5e4
rev12=$(printf '%s' "$rev" | cut -c1-12)
dest="$repo_root/resources/astrlink-guard/$rev12"
base="https://huggingface.co/QuantumNous/astrlink-guard/resolve/$rev"

if ! command -v curl >/dev/null 2>&1; then
  printf '%s\n' "error: curl is required" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  printf '%s\n' "error: sha256sum or shasum is required" >&2
  exit 1
fi

size_file() { wc -c < "$1" | tr -d ' '; }

fetch_one() {
  rel=$1
  name=$2
  expected_size=$3
  expected_sha=$4
  out="$dest/$name"

  if [ -f "$out" ]; then
    if [ "$(size_file "$out")" = "$expected_size" ] &&
       [ "$(hash_file "$out")" = "$expected_sha" ]; then
      printf 'ok      %s\n' "$name"
      return 0
    fi
    printf 'invalid %s (size or sha256 mismatch); re-downloading\n' "$name" >&2
  fi

  tmp="$out.part"
  rm -f "$tmp"
  printf 'fetch   %s\n' "$name"
  if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 \
      --silent --show-error -o "$tmp" "$base/$rel"; then
    rm -f "$tmp"
    printf 'error: download failed: %s\n' "$rel" >&2
    return 1
  fi

  got_size=$(size_file "$tmp")
  if [ "$got_size" != "$expected_size" ]; then
    rm -f "$tmp"
    printf 'error: %s size mismatch: expected %s, got %s\n' \
      "$name" "$expected_size" "$got_size" >&2
    return 1
  fi

  got_sha=$(hash_file "$tmp")
  if [ "$got_sha" != "$expected_sha" ]; then
    rm -f "$tmp"
    printf 'error: %s sha256 mismatch: expected %s, got %s\n' \
      "$name" "$expected_sha" "$got_sha" >&2
    return 1
  fi

  mv "$tmp" "$out"
  printf 'verified %s\n' "$name"
}

mkdir -p "$dest"

fetch_one int8/model_int8.onnx \
  model_int8.onnx \
  330781 \
  0a070d3113615e33ba3b84d6bd486f663a377c04c4b056e7381732179f51832a

fetch_one int8/model_int8.onnx_data \
  model_int8.onnx_data \
  37124608 \
  0ba34216ceead01e0ae2dfd8e46d52b67e7aee80b04f722d9b758613a91c0067

fetch_one int8/tokenizer.json \
  tokenizer.json \
  1502881 \
  0cf3b235ef125658015a6c8026a5fe6f28088bf825101a990ec18a10200feef4

printf 'AstrLink model ready: %s\n' "$dest"

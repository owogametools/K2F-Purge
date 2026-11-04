#!/bin/sh
# Copy this working tree into a public companion clone.
# Default target: <repo>/../K2F-Purge
# Includes .github/workflows/release.yml. Excludes agent/Trellis dirs and build output.
set -eu

usage() {
  printf '%s\n' \
    "usage: $0 [--dry-run] [TARGET]" \
    "  Copy the K2F PURGE working tree into TARGET." \
    "  Default TARGET is the sibling clone ../K2F-Purge (next to this repo)." \
    "  --dry-run  list what rsync would copy/delete, then exit."
}

dry_run=0
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run|-n) dry_run=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf '%s\n' "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [ -n "$target" ]; then
        printf '%s\n' "error: unexpected argument: $1" >&2
        usage >&2
        exit 2
      fi
      target=$1
      ;;
  esac
  shift
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

if [ -z "$target" ]; then
  parent=$(CDPATH= cd -- "$repo_root/.." && pwd)
  target=$parent/K2F-Purge
else
  case "$target" in
    /*) ;;
    *)
      parent=$(CDPATH= cd -- "$(dirname -- "$target")" && pwd) || {
        printf '%s\n' "error: parent of target does not exist: $target" >&2
        exit 1
      }
      target=$parent/$(basename -- "$target")
      ;;
  esac
fi

if ! command -v rsync >/dev/null 2>&1; then
  printf '%s\n' "error: rsync is required" >&2
  exit 1
fi

if [ -e "$target" ] && [ ! -d "$target" ]; then
  printf '%s\n' "error: target exists and is not a directory: $target" >&2
  exit 1
fi

if [ -d "$target" ]; then
  # Root of a clone (.git dir) or worktree (.git file). A subdirectory of
  # some other repo is not a git repo of its own.
  is_git=0
  if [ -d "$target/.git" ] || [ -f "$target/.git" ]; then
    is_git=1
  fi
  if [ "$is_git" -eq 0 ]; then
    leftover=""
    for f in "$target"/* "$target"/.[!.]* "$target"/..?*; do
      if [ -e "$f" ] || [ -L "$f" ]; then
        leftover=$f
        break
      fi
    done
    if [ -n "$leftover" ]; then
      printf '%s\n' "error: target is not empty and not a git repo: $target" >&2
      exit 1
    fi
  fi
fi

# --exclude '.git/' both skips the source .git and protects the dest .git
# from --delete (rsync does not delete excluded dest paths).
set -- \
  -a --delete \
  --exclude '.git/' \
  --exclude '.trellis/' \
  --exclude '.claude/' \
  --exclude '.agents/' \
  --exclude '.grok/' \
  --exclude '.pi/' \
  --exclude 'build/' \
  --exclude '.mygo/' \
  --exclude 'dist/' \
  --exclude 'quarantine/' \
  --exclude '*.exe' \
  --exclude '.DS_Store' \
  --exclude 'Thumbs.db' \
  --exclude '/AGENTS.md'

if [ "$dry_run" -eq 1 ]; then
  set -- -n --out-format='%n' "$@"
  printf '%s\n' "dry-run: $repo_root -> $target"
fi

rsync "$@" "$repo_root/" "$target/"

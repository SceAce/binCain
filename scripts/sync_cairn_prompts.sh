#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/Cairn" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="$repo_root/integration/cairn/prompts/pwn"
target_dir="$1/cairn/src/cairn/dispatcher/prompts/pwn"

mkdir -p "$target_dir"
cp "$source_dir"/*.md "$target_dir"/
echo "synced integration/cairn/prompts/pwn to cairn/src/cairn/dispatcher/prompts/pwn"

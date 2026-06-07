#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" == "0" ]]; then
  mkdir -p /home/kali/workspace
  chown -R kali:kali /home/kali/workspace /home/kali/AGENTS.md /home/kali/templates 2>/dev/null || true
  if [[ $# -eq 0 ]]; then
    exec su -s /bin/bash kali
  fi
  cmd="$*"
  exec su -s /bin/bash kali -c "$cmd"
fi

if [[ $# -eq 0 ]]; then
  exec /bin/bash
fi

exec "$@"

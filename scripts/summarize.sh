#!/usr/bin/env bash
# summarize.sh DIR — prints a Markdown table from DIR/{baseline,upstream,hardened}.json
set -euo pipefail
dir="$1"
echo "| | baseline | upstream | hardened |"
echo "|---|---|---|---|"
row() { # label jq-expression
  printf '| %s |' "$1"
  for n in baseline upstream hardened; do printf ' %s |' "$(jq -r "$2" "$dir/$n.json")"; done
  echo
}
row "Size (MB)" '.size_mb'
row "Runs as" '.user'
row "Shell in image" '.shell'
row "App user can change app code" '.app_code_writable_by_runtime_user'
row "App user can write its data folder" '.data_writable'
row "OS packages (deb)" '.packages.deb // 0'
row "npm packages" '.packages.npm // 0'
row "OS CVEs, all" '.os_vulns.total'
row "OS CVEs, critical + high" '(.os_vulns.critical + .os_vulns.high)'
row "OS CVEs, critical + high with a fix" '.os_vulns.fixable_critical_high'
row "App CVEs, all" '.app_vulns.total'
row "App CVEs, critical + high" '(.app_vulns.critical + .app_vulns.high)'

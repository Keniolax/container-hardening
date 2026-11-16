#!/usr/bin/env bash
# gate.sh MEASURE_JSON — fails unless the hardened image meets every rule below.
set -euo pipefail
m="$1"
fail=0
check() { # description jq-test
  if jq -e "$2" "$m" >/dev/null; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi
}
check "runs as a non-root user"                        '.user != "root" and .user != "" and (.user | startswith("0") | not)'
check "has no shell"                                   '.shell == false'
check "runtime user cannot change the app code"        '.app_code_writable_by_runtime_user == false'
check "no critical or high OS CVE that has a fix"      '.os_vulns.fixable_critical_high == 0'
exit "$fail"

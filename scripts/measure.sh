#!/usr/bin/env bash
# measure.sh NAME IMAGE OUTDIR
# Measures one local image and writes OUTDIR/NAME.json:
# size, packages by type, Trivy findings split into OS and application layers,
# the user it runs as, whether a shell exists, and whether that user can change the app code.
set -euo pipefail
name="$1"; image="$2"; out="$3"
mkdir -p "$out"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

size=$(docker image inspect -f '{{.Size}}' "$image")
user=$(docker image inspect -f '{{.Config.User}}' "$image")
layers=$(docker image inspect -f '{{len .RootFS.Layers}}' "$image")

syft scan "docker:$image" -q -o syft-json > "$tmp/syft.json"
trivy image --quiet --scanners vuln --format json --output "$tmp/trivy.json" "$image"
cp "$tmp/trivy.json" "$out/$name.trivy.json"

# Run a check with the image's own node binary, as the user the image runs as.
# Each check must print one of two words; anything else stops the script, so a check
# that cannot run is never read as a pass.
node_bin=""
for n in /nodejs/bin/node /usr/local/bin/node /usr/bin/node; do
  if docker run --rm --entrypoint "$n" "$image" -e '0' >/dev/null 2>&1; then node_bin="$n"; break; fi
done
[ -n "$node_bin" ] || { echo "no node binary found in $image" >&2; exit 1; }
probe() { # js-expression-printing-a-word  allowed-words...
  local js="$1"; shift
  local outw; outw=$(docker run --rm --entrypoint "$node_bin" "$image" -e "$js" 2>&1 | tail -1)
  for w in "$@"; do [ "$outw" = "$w" ] && { echo "$outw"; return; }; done
  echo "check failed to run: $outw" >&2; exit 1
}
# A shell in the image is what an attacker with code execution reaches for first.
shell=$(probe 'const fs=require("fs");console.log(["/bin/sh","/bin/bash","/bin/dash","/busybox/sh"].some(p=>fs.existsSync(p)))' true false)
# Can the user the image runs as change the application's own code?
code_writable=$(probe 'try{require("fs").appendFileSync("/juice-shop/build/app.js","");console.log("true")}catch(e){console.log(e.code==="EACCES"||e.code==="EROFS"||e.code==="EPERM"?"false":"error "+e.code)}' true false)
# The folders the app writes at run time must still be writable, or the image is broken.
data_writable=$(probe 'try{require("fs").writeFileSync("/juice-shop/data/.probe","");console.log("true")}catch(e){console.log(e.code==="EACCES"?"false":"error "+e.code)}' true false)

jq -n \
  --arg name "$name" --arg image "$image" --arg node "$node_bin" --arg user "${user:-root}" \
  --argjson size "$size" --argjson layers "$layers" \
  --argjson shell "$shell" --argjson code_writable "$code_writable" --argjson data_writable "$data_writable" \
  --slurpfile syft "$tmp/syft.json" --slurpfile trivy "$tmp/trivy.json" '
  def vulns(cls): [ $trivy[0].Results[]? | select(.Class == cls) | .Vulnerabilities[]? ]
                  | unique_by(.VulnerabilityID + "|" + .PkgName + "|" + .InstalledVersion);
  def count(v): {
      total: (v | length),
      critical: ([v[] | select(.Severity == "CRITICAL")] | length),
      high: ([v[] | select(.Severity == "HIGH")] | length),
      fixable_critical_high: ([v[] | select((.Severity == "CRITICAL" or .Severity == "HIGH") and ((.FixedVersion // "") != ""))] | length)
    };
  {
    name: $name, image: $image, user: $user,
    size_mb: ($size / 1048576 | floor), layers: $layers,
    shell: $shell, app_code_writable_by_runtime_user: $code_writable, data_writable: $data_writable, node: $node,
    packages: ($syft[0].artifacts | group_by(.type) | map({key: .[0].type, value: length}) | from_entries),
    os_vulns: count(vulns("os-pkgs")),
    app_vulns: count(vulns("lang-pkgs"))
  }' > "$out/$name.json"
cat "$out/$name.json"

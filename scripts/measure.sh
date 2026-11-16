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

# A shell in the image is what an attacker with code execution reaches for first.
if docker run --rm --entrypoint /bin/sh "$image" -c 'exit 0' >/dev/null 2>&1; then shell=true; else shell=false; fi
# Can the user the image runs as change the application's own code?
if docker run --rm --entrypoint node "$image" \
     -e 'require("fs").appendFileSync("/juice-shop/build/app.js", "")' >/dev/null 2>&1; then
  code_writable=true; else code_writable=false; fi

jq -n \
  --arg name "$name" --arg image "$image" --arg user "${user:-root}" \
  --argjson size "$size" --argjson layers "$layers" \
  --argjson shell "$shell" --argjson code_writable "$code_writable" \
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
    shell: $shell, app_code_writable_by_runtime_user: $code_writable,
    packages: ($syft[0].artifacts | group_by(.type) | map({key: .[0].type, value: length}) | from_entries),
    os_vulns: count(vulns("os-pkgs")),
    app_vulns: count(vulns("lang-pkgs"))
  }' > "$out/$name.json"
cat "$out/$name.json"

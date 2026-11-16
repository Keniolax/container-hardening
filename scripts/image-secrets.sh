#!/usr/bin/env bash
# image-secrets.sh IMAGE_REF OUTDIR
# Scans one image for secrets in two ways:
#   1. Trivy's secret scanner on the image;
#   2. gitleaks on each layer unpacked on its own, so a file that a later layer deletes is
#      still scanned.
# Writes OUTDIR/<name>.trivy-secrets.json, OUTDIR/<name>.layer-<n>.gitleaks.json and a summary.
# Findings are reported, not judged: the caller decides which are Juice Shop's planted secrets.
set -euo pipefail
ref="$1"; out="$2"
mkdir -p "$out"
name=$(echo "${ref##*/}" | tr ':@' '__' | cut -c1-80)
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

docker pull -q "$ref" > /dev/null
trivy image --quiet --scanners secret --format json --output "$out/$name.trivy-secrets.json" "$ref"
trivy_n=$(jq '[.Results[]?.Secrets[]?] | length' "$out/$name.trivy-secrets.json")

docker save "$ref" -o "$work/image.tar"
mkdir "$work/img" && tar -xf "$work/image.tar" -C "$work/img"
# Docker 25+ writes an OCI layout (index.json -> manifest -> blobs/sha256/...); older
# versions write manifest.json with layer paths. Build one list of layer files either way.
layers=(); config=""
if [ -f "$work/img/index.json" ]; then
  mf="$work/img/blobs/sha256/$(jq -r '.manifests[0].digest' "$work/img/index.json" | cut -d: -f2)"
  if jq -e '.manifests' "$mf" > /dev/null 2>&1; then   # an index: follow it to amd64
    mf="$work/img/blobs/sha256/$(jq -r '[.manifests[] | select(.platform.architecture == "amd64")][0].digest' "$mf" | cut -d: -f2)"
  fi
  config="$work/img/blobs/sha256/$(jq -r '.config.digest' "$mf" | cut -d: -f2)"
  while read -r l; do layers+=("$work/img/blobs/sha256/${l#sha256:}"); done < <(jq -r '.layers[].digest' "$mf")
else
  config="$work/img/$(jq -r '.[0].Config' "$work/img/manifest.json")"
  while read -r l; do layers+=("$work/img/$l"); done < <(jq -r '.[0].Layers[]' "$work/img/manifest.json")
fi
# The config holds ENV values and the build history (every RUN line), where a build-time
# secret would show.
mkdir "$work/config" && cp "$config" "$work/config/config.json"
gitleaks dir --no-banner -l error --redact --exit-code 0 -f json -r "$out/$name.config.gitleaks.json" "$work/config"
config_n=$(jq 'length' "$out/$name.config.gitleaks.json")
echo "config: env $(jq -c '.config.Env' "$work/config/config.json"), gitleaks findings $config_n"

n=0; leaks_total=0; files_total=0
for lf in "${layers[@]}"; do
  n=$((n + 1))
  d="$work/layer-$n"; mkdir "$d"
  tar --no-same-owner -xf "$lf" -C "$d"   # an extraction error stops the scan
  report="$out/$name.layer-$n.gitleaks.json"
  gitleaks dir --no-banner -l error --redact --exit-code 0 -f json -r "$report" "$d"
  c=$(jq 'length' "$report")
  leaks_total=$((leaks_total + c))
  f=$(find "$d" -type f | wc -l); files_total=$((files_total + f))
  echo "layer $n: $(du -sh "$d" | cut -f1), $f files, gitleaks findings $c"
  rm -rf "$d"
done
[ "$n" -gt 0 ] && [ "$files_total" -gt 1000 ] || { echo "FAIL  only $n layers / $files_total files read from $ref"; exit 1; }
echo "$ref: $n layers, $files_total files, trivy secrets $trivy_n, gitleaks findings $leaks_total in layers, $config_n in config" | tee -a "$out/summary.txt"

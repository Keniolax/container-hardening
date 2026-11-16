#!/usr/bin/env bash
# sigstore-bundles.sh IMAGE@DIGEST OUTDIR
# Downloads the Sigstore bundles that Cosign stored next to the image and prints, for each,
# its type, its transparency-log entry and its signing certificate's identity and dates.
# Reads the registry with GH_TOKEN. Fails if no bundle is found.
set -euo pipefail
ref="$1"; out="$2"
mkdir -p "$out"
digest="${ref#*@}"; repo="${ref%@*}"; path="${repo#ghcr.io/}"
tok=$(curl -fsS -u "x:${GH_TOKEN:?}" "https://ghcr.io/token?scope=repository:$path:pull" | jq -r .token)
get() { curl -fsS -H "Authorization: Bearer $tok" -H "Accept: $1" "https://ghcr.io/v2/$path/$2"; }
IDX='application/vnd.oci.image.index.v1+json'
MAN='application/vnd.oci.image.manifest.v1+json'

# OCI 1.1 referrers API first; Cosign falls back to a tag named after the digest.
if ! get "$IDX" "referrers/$digest" > "$out/referrers.json" 2>/dev/null; then
  get "$IDX" "manifests/sha256-${digest#sha256:}" > "$out/referrers.json"
fi
n=0
for m in $(jq -r '.manifests[].digest' "$out/referrers.json"); do
  get "$MAN" "manifests/$m" > "$out/m.json"
  for layer in $(jq -r '.layers[] | select(.mediaType | test("sigstore.bundle")) | .digest' "$out/m.json"); do
    n=$((n + 1))
    # Blobs redirect to storage, so follow redirects (-L).
    curl -fsSL -H "Authorization: Bearer $tok" "https://ghcr.io/v2/$path/blobs/$layer" > "$out/bundle-$n.json"
    echo "== bundle $n ($(jq -r '.artifactType // "?"' "$out/m.json"))"
    jq -r '.verificationMaterial.tlogEntries[]? |
      "tlog: logIndex \(.logIndex) integratedTime \((.integratedTime // "0") | tonumber | todate) kind \(.kindVersion.kind)/\(.kindVersion.version) logId \(.logId.keyId)"' \
      "$out/bundle-$n.json"
    jq -r '.verificationMaterial.certificate.rawBytes // .verificationMaterial.x509CertificateChain.certificates[0].rawBytes' \
      "$out/bundle-$n.json" | base64 -d > "$out/cert-$n.der"
    openssl x509 -inform DER -in "$out/cert-$n.der" -noout -issuer -startdate -enddate -ext subjectAltName \
      | sed 's/^/cert: /'
  done
done
rm -f "$out/m.json"
[ "$n" -gt 0 ] || { echo "FAIL  no Sigstore bundle found for $ref"; exit 1; }
echo "found $n bundle(s)"

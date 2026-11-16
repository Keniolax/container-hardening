#!/usr/bin/env bash
# verify-signature.sh IMAGE@DIGEST OUTDIR
# Verifies the signature and the SBOM attestation, then proves that verification fails
# for the wrong signer and for an image that differs from the signed one.
# Needs SIGNER, ISSUER and IMAGE in the environment.
set -euo pipefail
ref="$1"; out="$2"
mkdir -p "$out"

echo "== signature, expected signer"
cosign verify --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" "$ref" > "$out/verify.json"
jq -r '.[0].optional | "signed by \(.Subject // "?") issuer \(.Issuer // "?")"' "$out/verify.json" || true

echo "== SBOM attestation, expected signer"
cosign verify-attestation --type spdxjson \
  --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" "$ref" > "$out/verify-attestation.json"
jq -r '.payload' "$out/verify-attestation.json" | head -1 | base64 -d \
  | jq -r '"attestation subject \(.subject[0].name)@sha256:\(.subject[0].digest.sha256), predicate \(.predicateType), \(.predicate.packages | length) packages"'

must_fail() { # description command...
  local desc="$1"; shift
  if "$@" > /dev/null 2> "$out/neg.err"; then
    echo "FAIL  $desc: verification passed but must not"; exit 1
  fi
  echo "PASS  $desc: refused ($(tail -1 "$out/neg.err"))"
}

echo "== negative tests"
must_fail "wrong signer (another repo's workflow)" \
  cosign verify --certificate-identity "https://github.com/Keniolax/codeguardian-target/.github/workflows/security-gate.yml@refs/heads/main" \
  --certificate-oidc-issuer "$ISSUER" "$ref"
must_fail "wrong issuer" \
  cosign verify --certificate-identity "$SIGNER" --certificate-oidc-issuer "https://accounts.google.com" "$ref"

# The same image with one label changed: a new digest that was never signed.
tampered="$IMAGE:tampered-${GITHUB_SHA:-local}"
printf 'FROM %s\nLABEL tampered=true\n' "$ref" | docker build -q -t "$tampered" - > /dev/null
docker push -q "$tampered" > /dev/null
tref=$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$tampered" | grep "^$IMAGE@")
must_fail "changed image ($tref)" \
  cosign verify --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" "$tref"
echo "$tref" > "$out/tampered-ref.txt"

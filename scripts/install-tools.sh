#!/usr/bin/env bash
# Install the pinned tools into ./bin on a linux/amd64 runner.
# Each binary is checked against the sha256 its project published for that release.
set -euo pipefail

BIN="${BIN:-$PWD/bin}"
mkdir -p "$BIN"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() { # url sha256 out
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c -
}

fetch https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz \
  bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d "$TMP/syft.tgz"
tar -xzf "$TMP/syft.tgz" -C "$TMP" syft && install "$TMP/syft" "$BIN/syft"

fetch https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 \
  424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa "$TMP/cosign"
install "$TMP/cosign" "$BIN/cosign"

fetch https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz \
  c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0 "$TMP/trivy.tgz"
tar -xzf "$TMP/trivy.tgz" -C "$TMP" trivy && install "$TMP/trivy" "$BIN/trivy"

fetch https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64 \
  aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d "$TMP/kind"
install "$TMP/kind" "$BIN/kind"

fetch https://dl.k8s.io/release/v1.37.2/bin/linux/amd64/kubectl \
  c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4 "$TMP/kubectl"
install "$TMP/kubectl" "$BIN/kubectl"

"$BIN/syft" version | grep -m1 '^Version'
"$BIN/cosign" version 2>&1 | grep -m1 GitVersion
"$BIN/trivy" --version | head -1
"$BIN/kind" version
"$BIN/kubectl" version --client | head -1

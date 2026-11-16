# Run the hardened image in a local kind cluster with Pod Security and NetworkPolicy.
#   make cluster IMAGE_REF=ghcr.io/keniolax/container-hardening/juice-shop@sha256:...
#   make test-cluster
#   make verify IMAGE_REF=...      (checks the signature and the SBOM attestation)
#   make snapshot                  (JSON of pods, services, service accounts, policies)
#   make down
# Needs docker, kind, kubectl and cosign; scripts/install-tools.sh installs pinned
# linux/amd64 copies into ./bin.
SHELL := /bin/bash
export PATH := $(CURDIR)/bin:$(PATH)

CLUSTER     := hardening
SIGNER      ?= https://github.com/Keniolax/container-hardening/.github/workflows/build.yml@refs/heads/main
ISSUER      ?= https://token.actions.githubusercontent.com
export CURL_IMAGE  ?= curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
export DEBUG_IMAGE ?= gcr.io/distroless/nodejs24-debian13:debug-nonroot@sha256:4bbe32843b358db173c92768c585c2ecd5f70cff6571d573f2df2bfcd391c9a0

.PHONY: cluster test-cluster verify snapshot down

cluster:
	@test -n "$(IMAGE_REF)" || { echo "set IMAGE_REF=image@sha256:..."; exit 1; }
	@[[ "$(IMAGE_REF)" == *@sha256:* ]] || { echo "IMAGE_REF must name a digest, not a tag"; exit 1; }
	kind create cluster --config k8s/kind.yaml --wait 120s
	kubectl apply -f k8s/namespaces.yaml
	@if [ -n "$$GHCR_TOKEN" ]; then \
	  kubectl -n shop create secret docker-registry ghcr --docker-server=ghcr.io \
	    --docker-username="$$GHCR_USER" --docker-password="$$GHCR_TOKEN"; fi
	kubectl apply -f k8s/netpol.yaml
	sed "s|IMAGE_REF|$(IMAGE_REF)|g" k8s/juice-shop.yaml | kubectl apply -f -
	kubectl -n shop rollout status deploy/juice-shop --timeout=300s

test-cluster:
	scripts/cluster-test.sh

verify:
	@test -n "$(IMAGE_REF)" || { echo "set IMAGE_REF=image@sha256:..."; exit 1; }
	cosign verify --certificate-identity "$(SIGNER)" --certificate-oidc-issuer "$(ISSUER)" "$(IMAGE_REF)" > /dev/null
	cosign verify-attestation --type spdxjson --certificate-identity "$(SIGNER)" \
	  --certificate-oidc-issuer "$(ISSUER)" "$(IMAGE_REF)" > /dev/null
	@echo "signature and SBOM attestation verified for $(IMAGE_REF)"

snapshot:
	@kubectl get pods,services,serviceaccounts,networkpolicies -A -o json

down:
	kind delete cluster --name $(CLUSTER)

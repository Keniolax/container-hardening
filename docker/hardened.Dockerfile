# Hardened Juice Shop image. Differences from upstream's Dockerfile:
# - both bases are pinned by digest, so a rebuild uses the same bytes until a reviewed bump;
# - npm ci installs exactly what the lockfile says, and install-time telemetry is off;
# - the TypeScript build must produce build/app.js (upstream's postinstall hides a failed tsc);
# - no SBOM tool is installed in the build; Syft makes the SBOM from the finished image;
# - the app code is owned by root and read-only to the app user; only the five folders
#   Juice Shop writes at run time belong to UID 65532.

# node:24-trixie, resolved 2026-11-16. Debian 13, the same release as the runtime base,
# so the native sqlite3 module links against the same glibc.
FROM node:24-trixie@sha256:6e5d4c38403930b420404f190be8563396dca2bd156a6cb4722707b0efcf6fc1 AS installer
ENV SCARF_ANALYTICS=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false
COPY . /juice-shop
WORKDIR /juice-shop
RUN npm install -g typescript@6.0.3
RUN npm ci --omit=dev
RUN test -f build/app.js
RUN rm -rf frontend/node_modules frontend/.angular frontend/src/assets \
 && mkdir -p logs \
 && rm -f ftp/legal.md i18n/*.json

# gcr.io/distroless/nodejs24-debian13:nonroot, resolved 2026-11-16.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:6abfcb367ebc291572c774c1592a986be2ab26a2486f73093401327495a5962a
LABEL org.opencontainers.image.title="OWASP Juice Shop (hardened)" \
      org.opencontainers.image.version="20.3.0" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Keniolax/container-hardening"
WORKDIR /juice-shop
COPY --from=installer --chown=0:0 /juice-shop .
COPY --from=installer --chown=65532:0 /juice-shop/logs ./logs
COPY --from=installer --chown=65532:0 /juice-shop/ftp ./ftp
COPY --from=installer --chown=65532:0 /juice-shop/data ./data
COPY --from=installer --chown=65532:0 /juice-shop/i18n ./i18n
COPY --from=installer --chown=65532:0 /juice-shop/frontend/dist ./frontend/dist
USER 65532:65532
EXPOSE 3000
CMD ["/juice-shop/build/app.js"]

# An image for the CoreLink server, built from the published release tarball.
#
# A self-hosted install pulls ghcr.io/tech-blend-consulting/corelink-server. This
# downloads the release you name, checks it against the published checksums and
# unpacks it; there is nothing to compile and no source needed. The image carries
# the migration runner (/app/migrate), so the compose file's migrate and seed
# services use this same image and there is no separate migrate image.
#
#   docker build --build-arg VERSION=1.28.3 -t corelink-server:1.28.3 .
#
# For a host on a different architecture, pass TARGETARCH (amd64 or arm64) or let
# buildx set it:
#
#   docker buildx build --platform linux/arm64 --build-arg VERSION=1.28.3 .

FROM alpine:3.23 AS fetch

ARG VERSION
ARG TARGETARCH=amd64
ARG REGISTRY=https://usecorelink.com

RUN test -n "$VERSION" || (echo "VERSION is required, e.g. --build-arg VERSION=1.28.3" >&2; exit 1)

# The checksums file is published beside the archives. Verify before unpacking:
# a tarball that does not match is a failed build, not a warning. Archives
# built on macOS before COPYFILE_DISABLE was exported carry "._name" files
# beside every file; they are dropped, so bin/ empties and nothing of the kind
# reaches the image.
RUN apk add --no-cache curl ca-certificates \
 && mkdir -p /dl /app \
 && cd /dl \
 && curl -fsSL -O "${REGISTRY}/static/downloads/v${VERSION}/corelink-server-v${VERSION}-linux-${TARGETARCH}.tar.gz" \
 && curl -fsSL -O "${REGISTRY}/static/downloads/v${VERSION}/corelink-v${VERSION}-checksums.txt" \
 && grep " corelink-server-v${VERSION}-linux-${TARGETARCH}.tar.gz\$" "corelink-v${VERSION}-checksums.txt" > server.sha256 \
 && sha256sum -c server.sha256 \
 && tar xzf "corelink-server-v${VERSION}-linux-${TARGETARCH}.tar.gz" -C /app \
 && find /app -name '._*' -delete \
 && mv /app/bin/tbcl-server /app/bin/migrate /app/ \
 && rmdir /app/bin \
 && mv /app/migrations /migrations \
 && mkdir -p /app/configs /app/data

FROM alpine:3.23

ARG VERSION=dev

LABEL org.opencontainers.image.title="CoreLink server" \
      org.opencontainers.image.description="CoreLink secrets management server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/Tech-Blend-Consulting/corelink-apps"

RUN apk add --no-cache ca-certificates tzdata wget \
 && addgroup -g 1000 secrets \
 && adduser -u 1000 -G secrets -s /sbin/nologin -D secrets

WORKDIR /app

# /app holds tbcl-server, migrate, web/, connectors/ and CHANGELOG.md;
# /migrations is the goose directory /app/migrate reads by default.
COPY --from=fetch --chown=secrets:secrets /app /app
COPY --from=fetch /migrations /migrations

USER secrets:secrets

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

# Runtime configuration is supplied by the orchestrator, not baked in.
ENTRYPOINT ["/app/tbcl-server"]
CMD []

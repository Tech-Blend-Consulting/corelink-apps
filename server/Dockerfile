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
# The architecture comes from BuildKit's TARGETARCH, which is the --platform being
# built (the host's when none is given). It must not have a default here: a
# default overrides BuildKit's value, which is how every linux/arm64 image up to
# v1.28.52 shipped amd64 binaries. The build fails if the binary in the image is
# not the architecture it is labelled:
#
#   docker buildx build --platform linux/arm64 --build-arg VERSION=1.28.3 .

FROM alpine:3.23 AS fetch

ARG VERSION
ARG TARGETARCH
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

# The binary must be the architecture this image is built for, which is the one
# this stage runs as (uname -m), whatever TARGETARCH says: ELF machine 3e is
# x86-64, b7 is AArch64 (byte 18 of the header).
RUN case "$(uname -m)" in x86_64) want=3e ;; aarch64) want=b7 ;; \
      *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; esac \
 && got=$(od -An -tx1 -j18 -N1 /app/tbcl-server | tr -d ' ') \
 && if [ "$got" != "$want" ]; then echo "/app/tbcl-server is not $(uname -m) (ELF machine $got, TARGETARCH $TARGETARCH)" >&2; exit 1; fi

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

# On PATH so `docker compose exec tbcl-server tbcl-server setup-link` resolves.
RUN ln -s /app/tbcl-server /usr/local/bin/tbcl-server

USER secrets:secrets

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/health || exit 1

# Runtime configuration is supplied by the orchestrator, not baked in.
ENTRYPOINT ["/app/tbcl-server"]
CMD []

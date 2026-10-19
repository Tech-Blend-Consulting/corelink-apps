# An image for the CoreLink connector, built from the published binary.
#
# The connector is distributed as a binary from the registry, not as a container
# image, so this is how a Kubernetes deployment gets one. It downloads the
# release you name and runs it; there is nothing to compile and no source needed.
#
#   docker build --build-arg VERSION=1.28.2 -t corelink-connector:1.28.2 .
#
# The architecture comes from BuildKit's TARGETARCH, which is the --platform being
# built (the host's when none is given). It must not have a default here: a
# default overrides BuildKit's value, which is how every linux/arm64 image up to
# v1.28.52 shipped amd64 binaries. The build fails if the binary in the image is
# not the architecture it is labelled:
#
#   docker buildx build --platform linux/arm64 --build-arg VERSION=1.28.2 .

FROM alpine:3.20 AS fetch

ARG VERSION
ARG TARGETARCH
ARG REGISTRY=https://usecorelink.com

RUN test -n "$VERSION" || (echo "VERSION is required, e.g. --build-arg VERSION=1.28.2" >&2; exit 1)

RUN apk add --no-cache curl ca-certificates \
 && curl -fsSL -o /tmp/connector.tar.gz \
      "${REGISTRY}/static/downloads/v${VERSION}/corelink-transit-agent-v${VERSION}-linux-${TARGETARCH}.tar.gz" \
 && tar xzf /tmp/connector.tar.gz -C /tmp \
 && mv /tmp/corelink-transit-agent /usr/local/bin/corelink-transit-agent \
 && chmod +x /usr/local/bin/corelink-transit-agent

# The binary must be the architecture this image is built for, which is the one
# this stage runs as (uname -m), whatever TARGETARCH says: ELF machine 3e is
# x86-64, b7 is AArch64 (byte 18 of the header).
RUN case "$(uname -m)" in x86_64) want=3e ;; aarch64) want=b7 ;; \
      *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; esac \
 && got=$(od -An -tx1 -j18 -N1 /usr/local/bin/corelink-transit-agent | tr -d ' ') \
 && if [ "$got" != "$want" ]; then echo "/usr/local/bin/corelink-transit-agent is not $(uname -m) (ELF machine $got, TARGETARCH $TARGETARCH)" >&2; exit 1; fi

FROM alpine:3.20

# image.source is what a registry and a tooling chain read to get from an image
# back to the repository it was built from; without it this image described
# neither its origin nor itself. No image.licenses label: this repository states
# no licence, and the node SDK says UNLICENSED, so any SPDX value here would be
# an invented claim.
LABEL org.opencontainers.image.source="https://github.com/Tech-Blend-Consulting/corelink-apps" \
      org.opencontainers.image.description="CoreLink connector: serves envelopes it holds no key to open"

# ca-certificates so the connector can verify the platform's TLS.
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 corelink

COPY --from=fetch /usr/local/bin/corelink-transit-agent /usr/local/bin/corelink-transit-agent

# Nothing here needs root, and the connector holds no readable secret anyway.
USER 10001

# Envelopes on 9092, the CONNECT tunnel on 9091. Bind the envelope cache wider
# than loopback when applications in other pods need it -- what it serves is
# ciphertext under a key this process does not hold.
EXPOSE 9091 9092

ENTRYPOINT ["/usr/local/bin/corelink-transit-agent"]

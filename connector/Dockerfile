# An image for the CoreLink connector, built from the published binary.
#
# The connector is distributed as a binary from the registry, not as a container
# image, so this is how a Kubernetes deployment gets one. It downloads the
# release you name and runs it; there is nothing to compile and no source needed.
#
#   docker build --build-arg VERSION=1.28.2 -t corelink-connector:1.28.2 .
#
# For a cluster on a different architecture, pass TARGETARCH (amd64 or arm64) or
# let buildx set it:
#
#   docker buildx build --platform linux/arm64 --build-arg VERSION=1.28.2 .

FROM alpine:3.20 AS fetch

ARG VERSION
ARG TARGETARCH=amd64
ARG REGISTRY=https://usecorelink.com

RUN test -n "$VERSION" || (echo "VERSION is required, e.g. --build-arg VERSION=1.28.2" >&2; exit 1)

RUN apk add --no-cache curl ca-certificates \
 && curl -fsSL -o /tmp/connector.tar.gz \
      "${REGISTRY}/static/downloads/v${VERSION}/corelink-transit-agent-v${VERSION}-linux-${TARGETARCH}.tar.gz" \
 && tar xzf /tmp/connector.tar.gz -C /tmp \
 && mv /tmp/corelink-transit-agent /usr/local/bin/corelink-transit-agent \
 && chmod +x /usr/local/bin/corelink-transit-agent

FROM alpine:3.20

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

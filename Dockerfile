# HDAP node (v2 / Teleios) — multi-stage, no root at runtime.
#
#   docker build -t hdap-node:2.0.0 .
#   docker run -d --name hdap-node \
#     -p 8443:8443 \
#     -v hdap-data:/var/lib/hdap \
#     -e HDAP_ADVERTISE=meu-pyle.example.org:8443 \
#     hdap-node:2.0.0
#
# The master key is generated inside /var/lib/hdap on first boot. BACK IT UP
# together with hdap.db and tls.crt/tls.key: without it the blobs are unreadable.
FROM rust:1.95-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p hdap-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/hdap --create-home hdap
COPY --from=builder /build/target/release/hdap-server /usr/local/bin/hdap-server
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
USER hdap
ENV HDAP_LISTEN=0.0.0.0:8443 \
    HDAP_ADVERTISE=localhost:8443 \
    HDAP_DATA=/var/lib/hdap \
    HDAP_MASTER_KEY_FILE=/var/lib/hdap/master.key
VOLUME ["/var/lib/hdap"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD []

# A convesso relay in a container: UDP and TCP on port 7400, its identity in
# the volume at /data, created on first start and kept across restarts.
#
#   docker build -f docker/relay/Dockerfile -t convesso-relay .
#   docker run -d --name convesso-relay -p 7400:7400/udp -p 7400:7400/tcp \
#       -v convesso-relay-data:/data convesso-relay
#   docker logs convesso-relay        # prints the relay's address, which clients pin

FROM rust:1.95-slim-bookworm AS build
WORKDIR /src
# The workspace only: rust-toolchain.toml would bring in the embedded targets.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p convesso-tokio --features relay-bin --bin convesso-relay

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="convesso-relay" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/nohostalgia/convesso"
RUN useradd --system --uid 10001 --home-dir /data relay \
    && mkdir /data && chown relay /data
COPY --from=build /src/target/release/convesso-relay /usr/local/bin/convesso-relay
COPY docker/relay/relay.toml /etc/convesso/relay.toml
# The licence travels with the binary.
COPY LICENSE /usr/share/doc/convesso-relay/LICENSE
USER relay
VOLUME /data
EXPOSE 7400/udp 7400/tcp
ENTRYPOINT ["convesso-relay", "/etc/convesso/relay.toml"]

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        openssl \
        python3 \
        python3-pytest \
        tcpdump \
        tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . /workspace

RUN chmod +x /workspace/scripts/*.sh \
    && /workspace/scripts/generate-cert.sh

CMD ["sleep", "infinity"]

FROM ubuntu:22.04@sha256:ce4a593b4e323dcc3dd728e397e0a866a1bf516a1b7c31d6aa06991baec4f2e0

ARG NODE_MAJOR=20
ARG NODE_VERSION=20.20.2-1nodesource1
ARG DOCKER_VERSION=5:29.6.2-1~ubuntu.22.04~jammy
ARG CONTAINERD_VERSION=2.2.6-1~ubuntu.22.04~jammy
ARG OPENCODE_VERSION=1.15.12

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnupg \
        python3 \
        python3-pip \
        python3-venv \
        systemd \
        systemd-sysv \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/bin/python

RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        containerd.io="${CONTAINERD_VERSION}" \
        docker-ce="${DOCKER_VERSION}" \
        docker-ce-cli="${DOCKER_VERSION}" \
        nodejs="${NODE_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

ARG NPM_REGISTRY=https://registry.npmjs.org

RUN npm install --global "opencode-ai@${OPENCODE_VERSION}" \
        --registry "${NPM_REGISTRY}" \
        --fetch-retries 5 \
        --fetch-timeout 600000

RUN useradd --create-home --uid 1000 repro \
    && usermod --append --groups docker repro \
    && install -d -o repro -g repro /workspace \
    && install -d -o repro -g repro /home/repro/.config/opencode \
    && systemctl enable docker

WORKDIR /workspace
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

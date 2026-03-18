# Stage 1: Build Go binaries
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cli-box-server ./cmd/cli-box-server
    
# Stage 2: Runtime
FROM fedora:42

# GitHub CLI repo
RUN dnf install -y 'dnf-command(config-manager)' && \
    dnf config-manager addrepo --from-repofile=https://cli.github.com/packages/rpm/gh-cli.repo

# Google Cloud CLI repo
RUN printf '[google-cloud-cli]\nname=Google Cloud CLI\nbaseurl=https://packages.cloud.google.com/yum/repos/cloud-sdk-el9-x86_64\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=0\ngpgkey=https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg\n' \
    > /etc/yum.repos.d/google-cloud-sdk.repo

# Kubernetes repo
RUN printf '[kubernetes]\nname=Kubernetes\nbaseurl=https://pkgs.k8s.io/core:/stable:/v1.32/rpm/\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=https://pkgs.k8s.io/core:/stable:/v1.32/rpm/repodata/repomd.xml.key\n' \
    > /etc/yum.repos.d/kubernetes.repo

RUN dnf install -y \
    fuse3 \
    bubblewrap \
    vim-minimal \
    less \
    gh \
    awscli2 \
    google-cloud-cli \
    kubectl \
    && dnf clean all

COPY --from=build /out/cli-box-server /usr/local/bin/box
COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /work

VOLUME ["/work/state", "/work/secure", "/work/config"]

EXPOSE 443

ENTRYPOINT ["docker-entrypoint.sh"]

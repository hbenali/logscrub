# UNTESTED SKETCH. Base images are pinned by digest (Dependabot's docker
# ecosystem updates them); refresh with:
#   docker buildx imagetools inspect golang:1.26-alpine --format '{{.Manifest.Digest}}'
FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${REVISION}" \
      -o /out/logscrub ./cmd/logscrub

# distroless "static" has no shell or package manager, and :nonroot runs as uid 65532
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="logscrub" \
      org.opencontainers.image.description="Mask secrets and personal data in logs" \
      org.opencontainers.image.source="https://github.com/hbenali/logscrub" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/logscrub /logscrub
# already the default of the :nonroot base; stated so scanners (Trivy DS-0002) see it
USER 65532:65532
ENTRYPOINT ["/logscrub"]

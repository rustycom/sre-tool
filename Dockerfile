# Multi-stage build (SPEC §11). Both images are pinned by digest; see docs/VERSIONS.md.
FROM golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/sre-tool ./cmd/sre-tool

# Static binary on distroless: no shell, no package manager, nothing to exec into.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
COPY --from=build /out/sre-tool /sre-tool
USER 65532:65532
ENTRYPOINT ["/sre-tool"]

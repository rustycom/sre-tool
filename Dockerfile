# Multi-stage build. Both images are pinned by digest.
FROM golang:1.27.3@sha256:6928d94d1142af58816fed5a62338d605a266ccd53a0deaab6b1096f19059261 AS build
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

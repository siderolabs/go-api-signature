# syntax = docker/dockerfile-upstream:1.19.0-labs

# THIS FILE WAS AUTOMATICALLY GENERATED, PLEASE DO NOT EDIT.
#
# Generated on 2025-10-08T09:12:43Z by kres 063080a.

ARG TOOLCHAIN

# runs markdownlint
FROM docker.io/oven/bun:1.2.23-alpine AS lint-markdown
WORKDIR /src
RUN bun i markdownlint-cli@0.45.0 sentences-per-line@0.3.0
COPY .markdownlint.json .
COPY ./README.md ./README.md
RUN bunx markdownlint --ignore "CHANGELOG.md" --ignore "**/node_modules/**" --ignore '**/hack/chglog/**' --rules sentences-per-line .

# collects proto specs
FROM scratch AS proto-specs
ADD api/auth/auth.proto /api/auth/

# base toolchain image
FROM --platform=${BUILDPLATFORM} ${TOOLCHAIN} AS toolchain
RUN apk --update --no-cache add bash build-base curl jq protoc protobuf-dev

# build tools
FROM --platform=${BUILDPLATFORM} toolchain AS tools
ENV GO111MODULE=on
ARG CGO_ENABLED
ENV CGO_ENABLED=${CGO_ENABLED}
ARG GOTOOLCHAIN
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
ARG GOEXPERIMENT
ENV GOEXPERIMENT=${GOEXPERIMENT}
ENV GOPATH=/go
ARG GOIMPORTS_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go install golang.org/x/tools/cmd/goimports@v${GOIMPORTS_VERSION}
RUN mv /go/bin/goimports /bin
ARG GOMOCK_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go install go.uber.org/mock/mockgen@v${GOMOCK_VERSION}
RUN mv /go/bin/mockgen /bin
ARG PROTOBUF_GO_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go install google.golang.org/protobuf/cmd/protoc-gen-go@v${PROTOBUF_GO_VERSION}
RUN mv /go/bin/protoc-gen-go /bin
ARG GRPC_GO_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v${GRPC_GO_VERSION}
RUN mv /go/bin/protoc-gen-go-grpc /bin
ARG GRPC_GATEWAY_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v${GRPC_GATEWAY_VERSION}
RUN mv /go/bin/protoc-gen-grpc-gateway /bin
ARG VTPROTOBUF_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go install github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto@v${VTPROTOBUF_VERSION}
RUN mv /go/bin/protoc-gen-go-vtproto /bin
ARG DEEPCOPY_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go install github.com/siderolabs/deep-copy@${DEEPCOPY_VERSION} \
	&& mv /go/bin/deep-copy /bin/deep-copy
ARG GOLANGCILINT_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCILINT_VERSION} \
	&& mv /go/bin/golangci-lint /bin/golangci-lint
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go install golang.org/x/vuln/cmd/govulncheck@latest \
	&& mv /go/bin/govulncheck /bin/govulncheck
ARG GOFUMPT_VERSION
RUN go install mvdan.cc/gofumpt@${GOFUMPT_VERSION} \
	&& mv /go/bin/gofumpt /bin/gofumpt

# tools and sources
FROM tools AS base
WORKDIR /src
COPY go.mod go.mod
COPY go.sum go.sum
RUN cd .
RUN --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go mod download
RUN --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go mod verify
COPY ./api ./api
COPY ./pkg ./pkg
RUN --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go list -mod=readonly all >/dev/null

# runs protobuf compiler
FROM tools AS proto-compile
COPY --from=proto-specs / /
RUN protoc -I/api --grpc-gateway_out=paths=source_relative:/api --grpc-gateway_opt=generate_unbound_methods=true --go_out=paths=source_relative:/api --go-grpc_out=paths=source_relative:/api --go-vtproto_out=paths=source_relative:/api --go-vtproto_opt=features=marshal+unmarshal+size+equal+clone /api/auth/auth.proto
RUN rm /api/auth/auth.proto
RUN goimports -w -local github.com/siderolabs/go-api-signature /api
RUN gofumpt -w /api

# run go generate
FROM base AS go-generate-0
WORKDIR /src
COPY .license-header.go.txt hack/.license-header.go.txt
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg go generate ./internal/...
RUN goimports -w -local github.com/siderolabs/go-api-signature ./internal

# runs gofumpt
FROM base AS lint-gofumpt
RUN FILES="$(gofumpt -l .)" && test -z "${FILES}" || (echo -e "Source code is not formatted with 'gofumpt -w .':\n${FILES}"; exit 1)

# runs golangci-lint
FROM base AS lint-golangci-lint
WORKDIR /src
COPY .golangci.yml .
ENV GOGC=50
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/root/.cache/golangci-lint,id=go-api-signature/root/.cache/golangci-lint,sharing=locked --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg golangci-lint run --config .golangci.yml

# runs golangci-lint fmt
FROM base AS lint-golangci-lint-fmt-run
WORKDIR /src
COPY .golangci.yml .
ENV GOGC=50
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/root/.cache/golangci-lint,id=go-api-signature/root/.cache/golangci-lint,sharing=locked --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg golangci-lint fmt --config .golangci.yml
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/root/.cache/golangci-lint,id=go-api-signature/root/.cache/golangci-lint,sharing=locked --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg golangci-lint run --fix --issues-exit-code 0 --config .golangci.yml

# runs govulncheck
FROM base AS lint-govulncheck
WORKDIR /src
COPY --chmod=0755 hack/govulncheck.sh ./hack/govulncheck.sh
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg ./hack/govulncheck.sh ./...

# runs unit-tests with race detector
FROM base AS unit-tests-race
WORKDIR /src
ARG TESTPKGS
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg --mount=type=cache,target=/tmp,id=go-api-signature/tmp CGO_ENABLED=1 go test -race ${TESTPKGS}

# runs unit-tests
FROM base AS unit-tests-run
WORKDIR /src
ARG TESTPKGS
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-api-signature/root/.cache/go-build --mount=type=cache,target=/go/pkg,id=go-api-signature/go/pkg --mount=type=cache,target=/tmp,id=go-api-signature/tmp go test -covermode=atomic -coverprofile=coverage.txt -coverpkg=${TESTPKGS} ${TESTPKGS}

# cleaned up specs and compiled versions
FROM scratch AS generate
COPY --from=proto-compile /api/ /api/

# clean golangci-lint fmt output
FROM scratch AS lint-golangci-lint-fmt
COPY --from=lint-golangci-lint-fmt-run /src .

FROM scratch AS unit-tests
COPY --from=unit-tests-run /src/coverage.txt /coverage-unit-tests.txt


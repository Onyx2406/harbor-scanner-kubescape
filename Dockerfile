FROM golang:1.22-alpine AS builder

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o harbor-scanner-kubescape \
    ./cmd/scanner-kubescape

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

RUN addgroup -S scanner && adduser -S scanner -G scanner
USER scanner

COPY --from=builder /app/harbor-scanner-kubescape /usr/local/bin/harbor-scanner-kubescape

EXPOSE 8080

ENTRYPOINT ["harbor-scanner-kubescape"]

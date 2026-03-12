VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
IMAGE   ?= ghcr.io/goharbor/harbor-scanner-kubescape

.PHONY: build test lint docker-build docker-push clean

build:
	CGO_ENABLED=0 go build \
		-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)" \
		-o harbor-scanner-kubescape \
		./cmd/scanner-kubescape

test:
	go test -v -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run ./...

docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(IMAGE):$(VERSION) .

docker-push:
	docker push $(IMAGE):$(VERSION)

clean:
	rm -f harbor-scanner-kubescape coverage.out

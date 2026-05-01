# Harbor Scanner Adapter for Kubescape

A [Harbor](https://goharbor.io) scanner adapter that integrates [Kubescape](https://kubescape.io)'s image vulnerability scanning capabilities (powered by [Grype](https://github.com/anchore/grype) via [kubevuln](https://github.com/kubescape/kubevuln)) as a pluggable scanner in Harbor.

## Overview

This adapter implements the [Harbor Pluggable Scanner API v1.2](https://github.com/goharbor/pluggable-scanner-spec) and bridges Harbor's scanning workflow with Kubescape's `kubevuln` component for image vulnerability analysis.

### How It Works

1. **`GET /api/v1/metadata`** — Returns scanner capabilities. Harbor uses this to discover the scanner.
2. **`POST /api/v1/scan`** — Accepts a scan request from Harbor, triggers an image vulnerability scan via kubevuln's `ScanCVE` endpoint, and returns a scan ID.
3. **`GET /api/v1/scan/{scan_request_id}/report`** — Returns the vulnerability report. Harbor polls this until results are ready (HTTP 200) or the scan fails (HTTP 500). Returns HTTP 302 while scanning is in progress.

### Architecture

```
Harbor  →  harbor-scanner-kubescape  →  kubevuln (Kubescape)
                                           ↓
                                     Grype + Syft
                                           ↓
                                   VulnerabilityManifest CRD
```

## Prerequisites

- A running Harbor instance (v2.0+)
- Kubescape installed in the cluster with the `kubevuln` component running
- Helm 3 (for Kubernetes deployment)

## Quick Start

### Deploy with Helm

```bash
helm install harbor-scanner-kubescape ./charts/harbor-scanner-kubescape \
  --namespace harbor \
  --set scanner.kubevulnURL=http://kubevuln.kubescape.svc.cluster.local:8080
```

### Register in Harbor

1. Go to **Harbor Admin** → **Interrogation Services** → **Scanners**
2. Click **+ New Scanner**
3. Fill in:
   - **Name**: Kubescape
   - **Endpoint**: `http://harbor-scanner-kubescape.harbor.svc.cluster.local:8080`
     (or `https://...:8443` if you enabled TLS — see [TLS](#tls) below)
4. Click **Test Connection**, then **Add**

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SCANNER_API_ADDR` | `:8080` | Address for the HTTP server to listen on |
| `SCANNER_API_TLS_CERT` | _(unset)_ | Path to a PEM-encoded TLS certificate. When both cert and key are set, the server uses HTTPS. |
| `SCANNER_API_TLS_KEY` | _(unset)_ | Path to the PEM-encoded TLS private key. |
| `KUBEVULN_URL` | `http://kubevuln:8080` | Base URL of the kubevuln service |
| `KUBEVULN_NAMESPACE` | `kubescape` | Kubernetes namespace for Kubescape components |
| `SCAN_REUSE_TTL` | `24h` | Freshness window for reusing an existing VulnerabilityManifest CRD. Older CRDs are treated as stale and trigger a fresh scan so newly disclosed CVEs are picked up. Set to `0` to disable reuse. |
| `MEMORY_STORE_RETENTION` | `1h` | How long Finished/Failed scan jobs are kept in memory before eviction. Long enough to outlast Harbor's poll loop. Set to `0` to disable eviction (only sensible for tests). |
| `MEMORY_STORE_CLEANUP_INTERVAL` | `5m` | How often the in-memory janitor runs. |

### TLS

By default the adapter serves plain HTTP on `:8080` and TLS termination is
expected at the cluster edge (ingress / service mesh). To serve HTTPS directly,
set both `SCANNER_API_TLS_CERT` and `SCANNER_API_TLS_KEY` to mounted PEM file
paths and typically set `SCANNER_API_ADDR` to `:8443`.

When deploying with the Helm chart, enable TLS via:

```bash
kubectl create secret tls harbor-scanner-kubescape-tls \
  --cert=path/to/tls.crt --key=path/to/tls.key -n harbor

helm install harbor-scanner-kubescape ./charts/harbor-scanner-kubescape \
  --namespace harbor \
  --set tls.enabled=true \
  --set tls.secretName=harbor-scanner-kubescape-tls \
  --set scanner.apiAddr=":8443" \
  --set service.port=8443
```

### Replicas

Scan state is held in an in-memory store, so the chart only supports
`replicaCount: 1`. Installing with a higher replica count is rejected by a
chart-level validation; you can opt out via `--set acknowledgeUnsafeMultiReplica=true`
but Harbor polls will return 404 for jobs that landed on a different replica.
See [#2](https://github.com/goharbor/harbor-scanner-kubescape/issues/2) for the
shared-backend plan.

## Development

### Build

```bash
make build
```

### Test

```bash
make test
```

### Docker

```bash
make docker-build VERSION=0.1.0
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/metadata` | Scanner metadata and capabilities |
| `POST` | `/api/v1/scan` | Accept scan request |
| `GET` | `/api/v1/scan/{id}/report` | Get scan report |
| `GET` | `/probe/healthy` | Liveness probe |
| `GET` | `/probe/ready` | Readiness probe |

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Related Projects

- [Harbor](https://github.com/goharbor/harbor)
- [Kubescape](https://github.com/kubescape/kubescape)
- [kubevuln](https://github.com/kubescape/kubevuln)
- [harbor-scanner-trivy](https://github.com/goharbor/harbor-scanner-trivy) (reference implementation)

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
   - **Endpoint**: `http://harbor-scanner-kubescape.harbor.svc.cluster.local:8443`
4. Click **Test Connection**, then **Add**

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SCANNER_API_ADDR` | `:8443` | Address for the HTTP server to listen on |
| `KUBEVULN_URL` | `http://kubevuln:8080` | Base URL of the kubevuln service |
| `KUBEVULN_NAMESPACE` | `kubescape` | Kubernetes namespace for Kubescape components |

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

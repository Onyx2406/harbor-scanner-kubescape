# Contributing

Thanks for your interest in contributing to `harbor-scanner-kubescape`.

This project is a Harbor scanner adapter for Kubescape and is currently maintained by Nucleus Systems as a community integration pending donation to the `goharbor` organization.

## How to contribute

1. Open an issue describing the bug, feature, or documentation improvement.
2. Fork the repository and create a focused branch.
3. Keep changes small and reviewable.
4. Add or update tests when changing behaviour.
5. Run the test suite before opening a pull request:

```bash
go test ./...
```

## Development notes

- The adapter implements the Harbor Pluggable Scanner API.
- Kubescape's `kubevuln` component performs the underlying vulnerability scan.
- Keep Harbor and Kubescape compatibility in mind when changing API behaviour.
- Prefer clear, operationally useful documentation over broad claims.

## Security issues

Please do not report security vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

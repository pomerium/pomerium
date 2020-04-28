# Integration Tests
These tests are full end-to-end integration tests using Pomerium in a kubernetes cluster.

## Usage
The following applications are needed:

* `kubectl`: to apply the manifests to kubernetes
* `mkcert`: to generate a root CA and wildcard certificates

The test suite will apply the manifests to your current Kubernetes context before running the tests.

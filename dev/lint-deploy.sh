#!/usr/bin/env bash
# Lints the deployment files (make lint-deploy; on the host or in CI): the Helm chart
# (helm lint, then helm template validated with kubeconform -strict together with the
# plain DaemonSet), and the GitHub Actions workflow (actionlint). The tools run with
# `go run` at pinned versions; kubeconform fetches the Kubernetes JSON schemas.
set -euo pipefail
cd "$(dirname "$0")/.."

HELM=helm.sh/helm/v3/cmd/helm@v3.22.1
KUBECONFORM=github.com/yannh/kubeconform/cmd/kubeconform@v0.8.0
ACTIONLINT=github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
KUBE_VERSION=${KUBE_VERSION:-1.33.0}

tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT

go run "$HELM" lint deploy/helm/portwarden-agent
for set in "" "--set nats.caSecret=nats-ca --set nats.credentialType=creds --set nats.credentialKey=host.creds --set seccompProfile=Unconfined"; do
	# shellcheck disable=SC2086 # $set is a list of flags
	go run "$HELM" template pw deploy/helm/portwarden-agent --namespace portwarden --kube-version "$KUBE_VERSION" $set >"$tmp/rendered.yaml"
	go run "$KUBECONFORM" -strict -summary -kubernetes-version "$KUBE_VERSION" "$tmp/rendered.yaml" deploy/kubernetes/daemonset.yaml
done
if go run "$HELM" template pw deploy/helm/portwarden-agent --kube-version "$KUBE_VERSION" --set nats.credentialType=bogus >/dev/null 2>&1; then
	echo "lint-deploy: a bad nats.credentialType rendered" >&2
	exit 1
fi
go run "$ACTIONLINT" .github/workflows/*.yml
echo "lint-deploy: ok"

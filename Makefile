# Kernel-touching targets run inside the Lima VM named "portwarden" (see dev/lima.yaml).
VM := portwarden
REPO := $(CURDIR)

.PHONY: vm generate test itest e2e install-agent dist dist-check dist-lint lint-deploy matrix

# Re-runnable: starts the existing instance, or creates it from dev/lima.yaml.
vm:
	@if limactl list -q | grep -qx $(VM); then limactl start $(VM); else limactl start --name=$(VM) dev/lima.yaml; fi

generate:
	limactl shell $(VM) bash -lc 'cd $(REPO) && buf generate && go generate ./...'

test:
	go test ./...

# Builds the test binaries as the VM user and runs only them as root (dev/itest.sh).
itest:
	limactl shell $(VM) bash -lc 'cd $(REPO) && dev/itest.sh'

e2e:
	limactl shell $(VM) bash -lc 'cd $(REPO) && dev/e2e.sh'

# Builds, installs and enables the portwarden-agent systemd unit in the VM (dev/install-agent.sh).
install-agent:
	limactl shell $(VM) bash -lc 'cd $(REPO) && dev/install-agent.sh'

# Release artifacts in dist/ (on the host): linux/amd64 and linux/arm64 binaries, .debs,
# SBOMs and SHA256SUMS (dev/dist.sh). VERSION=1.2.3 overrides the derived version.
dist:
	dev/dist.sh

# Builds everything again in a temp dir and fails unless it is byte-identical to dist/.
dist-check:
	dev/dist.sh --check

# dpkg-deb and lintian over dist/*.deb, in the VM (dev/dist-lint.sh).
dist-lint:
	limactl shell $(VM) bash -lc 'cd $(REPO) && dev/dist-lint.sh'

# helm lint, kubeconform over the chart and DaemonSet, actionlint (dev/lint-deploy.sh).
lint-deploy:
	dev/lint-deploy.sh

# Kernel matrix on the host: Ubuntu 24.04 and 26.04 VMs (itest + e2e) and an x86_64 VM
# (cross-compiled tests, the amd64 .deb). MATRIX_LEGS="2604" picks legs (dev/matrix.sh).
matrix:
	dev/matrix.sh

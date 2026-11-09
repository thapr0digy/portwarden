# Kernel-touching targets run inside the Lima VM named "portwarden" (see dev/lima.yaml).
VM := portwarden
REPO := $(CURDIR)

.PHONY: vm generate test fuzz itest e2e install-agent dist dist-check dist-lint lint-deploy matrix vm-verify dev-test

# Re-runnable: starts the existing instance, or creates it from dev/lima.yaml.
vm:
	@if limactl list -q | grep -qx $(VM); then limactl start $(VM); else limactl start --name=$(VM) dev/lima.yaml; fi

generate:
	limactl shell $(VM) bash -lc 'cd $(REPO) && buf generate && go generate ./...'

test:
	go test ./...

# Native Go fuzzing of every parser of untrusted input, FUZZTIME each (Go runs one fuzz
# target per invocation). Stops at the first crash; its input lands in the package's
# testdata/fuzz/<Target>/, which go test then replays. Deep runs: README "Fuzzing".
FUZZTIME ?= 30s
FUZZMINIMIZETIME ?= 10s
FUZZ_TARGETS := \
	internal/exposure/nft:FuzzParse \
	internal/exposure/iptables:FuzzParse \
	internal/proxy/nginx:FuzzLoad \
	internal/proxy/apache:FuzzLoad \
	internal/proxy/haproxy:FuzzLoad \
	internal/redact:FuzzCmdline \
	internal/spool:FuzzDecodeRecord \
	internal/spool:FuzzOpen \
	internal/inventory:FuzzHandle

fuzz:
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t##*:}; \
		echo "== fuzz $$pkg $$name ($(FUZZTIME))"; \
		go test -run '^$$' -fuzz "^$$name\$$" -fuzztime $(FUZZTIME) -fuzzminimizetime $(FUZZMINIMIZETIME) ./$$pkg \
			|| { echo "fuzz: $$pkg $$name failed"; exit 1; }; \
	done

# Host-only tests of the dev scripts: the VM lock and vm-verify's file list (dev/vmlock-test.sh).
dev-test:
	dev/vmlock-test.sh

# Builds the test binaries as the VM user and runs only them as root (dev/itest.sh).
# itest and e2e take the VM lock (dev/vmlock.sh) and wait until the VM runs no tests.
itest:
	dev/vmlock.sh run --vm $(VM) -- limactl shell $(VM) bash -lc 'cd $(REPO) && dev/itest.sh'

e2e:
	dev/vmlock.sh run --vm $(VM) -- limactl shell $(VM) bash -lc 'cd $(REPO) && dev/e2e.sh'

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

# The kernel matrix for this checkout from anywhere (a Flowryn or other worktree the VMs do
# not mount): copies it under ~/projects/portwarden/.vmverify/ and runs dev/matrix.sh
# there (dev/vm-verify.sh). MATRIX_LEGS="2604" picks legs.
vm-verify:
	dev/vm-verify.sh --legs "$(or $(MATRIX_LEGS),2404 2604 amd64)"

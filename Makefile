# Kernel-touching targets run inside the Lima VM named "lw" (see dev/lima.yaml).
VM := lw
REPO := $(CURDIR)

.PHONY: vm generate test itest e2e install-agent

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

# Builds, installs and enables the lw-agent systemd unit in the VM (dev/install-agent.sh).
install-agent:
	limactl shell $(VM) bash -lc 'cd $(REPO) && dev/install-agent.sh'

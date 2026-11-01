# Kernel-touching targets run inside the Lima VM named "lw" (see dev/lima.yaml).
VM := lw
REPO := $(CURDIR)

.PHONY: vm generate test itest e2e

vm:
	limactl start --name=$(VM) dev/lima.yaml

generate:
	limactl shell $(VM) bash -lc 'cd $(REPO) && buf generate && go generate ./...'

test:
	go test ./...

itest:
	limactl shell $(VM) bash -lc 'cd $(REPO) && sudo -E env "PATH=$$PATH" go test -tags integration ./...'

e2e:
	limactl shell $(VM) bash -lc 'cd $(REPO) && dev/e2e.sh'

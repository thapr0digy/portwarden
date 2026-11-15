package access

import (
	"io/fs"
	"sync"
	"testing/fstest"
)

// Public keys and their fingerprints as ssh-keygen -l prints them.
const (
	caVault   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0Xshq1p0+wDrYeS4zT9hvujKFEJ6y+ZqjTDE2B1iDT vault ssh/prod"
	caVaultFP = "SHA256:XwOh4qn0x9RTx0vJMDxDEA8QC1d4LRwshcnnBWIN0qQ"
	caLocal   = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDtlUKIR5Wpp9gtQNZBpbV1EUiatj96wOqtHbuagp1eDvMNhzfblAX1voe8tsYlKl0fG4pR3OhDxRd5Vbv46CusNj15M3rxt51BODBNUmSIbmgBmar2DGwDpJhOwkn5i3WZM6AiLnyBbnixfdPjhgYdBsSX/akLrkmJtuzmUFw13E1MB/fGb0ruyMW5k/9Ta/+sIZP9HTWh0aD5FhvHB4vRvjonOi86XJirbCR/FFqDnCOZ+LLfDTTlDspmN6MPz3MgjHGvIknMYxM7aDCJncMCmQkKZHTsepHxItEuBQKFoEmmYGIK6VOGah8fte/EonwZZuAN7oaDhNYN3F9eRUoF host-local"
	caLocalFP = "SHA256:yZY9T4riCJZwNubvq/iT8zYUtjel/WDFW0Bux72F+J4"
	// underpantsFP stands for a shared key's fingerprint (any well-formed one will do).
	underpantsFP = "SHA256:I8mg+yasAvN5VKOREFoeN54OIuc1hm+LJL6KAGScwsI"
)

// ansibleHost is a host as Ansible's base role leaves it: sshd trusts Vault's CA through a
// drop-in, principals per user, pants's sudo rule in a 0644 drop-in, /etc/sudoers 0440 root.
func ansibleHost() *hostFS {
	return &hostFS{files: fstest.MapFS{
		"etc/ssh/sshd_config": {Data: []byte(`# Ubuntu's sshd_config
Include /etc/ssh/sshd_config.d/*.conf
KbdInteractiveAuthentication no
UsePAM yes
PasswordAuthentication yes
Subsystem sftp /usr/lib/openssh/sftp-server
`)},
		"etc/ssh/sshd_config.d/10-vault.conf": {Data: []byte(`TrustedUserCAKeys /etc/ssh/ssh_trusted_user_ca_keys
AuthorizedPrincipalsFile /etc/ssh/authorized_principals/%u
PasswordAuthentication no
PermitRootLogin no
Match User backup
	AuthorizedKeysFile none
`)},
		"etc/ssh/ssh_trusted_user_ca_keys":    {Data: []byte("# Vault\n" + caVault + "\n\nnot a key\n" + caLocal + "\n" + caVault + "\n")},
		"etc/ssh/authorized_principals/pants": {Data: []byte("pants\n# deploys\nfrom=\"10.0.0.0/8,192.0.2.1\" deploy\n")},
		"etc/passwd":                          {Data: []byte("root:x:0:0:root:/root:/bin/bash\npants:x:1000:1000::/home/pants:/bin/bash\n")},
		"etc/group":                           {Data: []byte("root:x:0:\nsudo:x:27:pants\npants:x:1000:\n")},
		"etc/sudoers":                         {Data: []byte("root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n")},
		"etc/sudoers.d/README":                {Data: []byte("# Files in this directory are read by sudo.\n")},
		"etc/sudoers.d/pants":                 {Data: []byte("pants ALL=(ALL) NOPASSWD: ALL\n")},
		"etc/sudoers.d/old~":                  {Data: []byte("pants ALL=(ALL) PASSWD: ALL\n")},
	}, deny: map[string]bool{"etc/sudoers": true}}
}

// hostFS is a host's file system in memory, with files the agent may not read (open fails
// with permission denied), safe to change while a reader polls it. It implements only
// Open, so ReadDir and Glob go through it too.
type hostFS struct {
	mu    sync.Mutex
	files fstest.MapFS
	deny  map[string]bool
}

func (h *hostFS) Open(name string) (fs.File, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.deny[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	// A copy: the returned file must not see a later write.
	return fstest.MapFS(cloneMap(h.files)).Open(name)
}

func (h *hostFS) write(name, data string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[name] = &fstest.MapFile{Data: []byte(data)}
}

func cloneMap(m fstest.MapFS) fstest.MapFS {
	out := make(fstest.MapFS, len(m))
	for k, v := range m {
		c := *v
		out[k] = &c
	}
	return out
}

// Package natsauth defines the NATS users Portwarden needs and their least-privilege
// permissions (design §6: each server may publish only under its own asm.<host> prefix),
// mints nkey users for them and renders the nats-server authorization block.
//
// Roles:
//   - host: one per server. Publishes only the agent's own subjects under asm.<host>
//     (HostSubjects); subscribes only to its own reply inboxes _INBOX_<host>.> (JetStream
//     publish acks). It can never publish in the backend's pwb.> namespace, so it cannot
//     forge a cloud or verifier verdict, even about itself.
//   - inventory, alerter, verifier: backend services. Each may read the ASM_EVENTS stream
//     through its own named durable consumers only, and subscribe only to its own inboxes
//     _INBOX_<service>.>. None may publish under asm.>. The inventory publishes cloud
//     verdicts (pwb.cloud.<host>.exposure) and probe requests (pwb.probe.<host>.request)
//     and fetches single stream messages (gap reload); the verifier publishes its results
//     (pwb.verifier.<host>.exposure). The alerter publishes nothing on the bus.
//   - admin: creates and manages the stream ($JS.API.>), never given to a host.
package natsauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/nats-io/nkeys"
)

// StreamName is the JetStream stream every Portwarden event goes to.
const StreamName = "ASM_EVENTS"

// Role is a kind of NATS user.
type Role string

const (
	RoleHost      Role = "host"
	RoleInventory Role = "inventory"
	RoleAlerter   Role = "alerter"
	RoleVerifier  Role = "verifier"
	RoleAdmin     Role = "admin"
)

// Durable consumer names. Each service may create, read, ack and delete only its own.
const (
	ConsumerInventory = "pw-inventory"
	ConsumerAlerter   = "pw-alerter"
	ConsumerAlerterHB = "pw-alerter-hb"
	ConsumerVerifier  = "pw-verifier"
	consumerAPIPrefix = "$JS.API.CONSUMER."
	streamInfoSubject = "$JS.API.STREAM.INFO." + StreamName
	streamMsgGet      = "$JS.API.STREAM.MSG.GET." + StreamName
	directGetWildcard = "$JS.API.DIRECT.GET." + StreamName + ".>"
	directGetPlain    = "$JS.API.DIRECT.GET." + StreamName
	jetStreamAPIInfo  = "$JS.API.INFO"
	ackPrefix         = "$JS.ACK." + StreamName + "."
	cloudVerdicts     = "pwb.cloud.*.exposure"
	probeRequests     = "pwb.probe.*.request"
	verifierResults   = "pwb.verifier.*.exposure"
)

// HostSubjects are the subject kinds an agent publishes under asm.<host>.
var HostSubjects = []string{"listener.opened", "listener.closed", "listener.owner_changed", "exposure.changed",
	"snapshot", "heartbeat", "proxy.routes", "host.changed"}

// reservedHostIDs would give a host a service's reply inbox (_INBOX_<service>).
var reservedHostIDs = map[string]bool{"inventory": true, "alerter": true, "verifier": true, "admin": true}

// Consumers lists the durable consumers a service role owns.
func Consumers(r Role) []string {
	switch r {
	case RoleInventory:
		return []string{ConsumerInventory}
	case RoleAlerter:
		return []string{ConsumerAlerter, ConsumerAlerterHB}
	case RoleVerifier:
		return []string{ConsumerVerifier}
	}
	return nil
}

// InboxPrefix is the reply-inbox prefix a user of role r (and host id, for hosts) must
// use: _INBOX_<host> for a host, _INBOX_<service> for a service, _INBOX for the admin.
func InboxPrefix(r Role, host string) string {
	switch r {
	case RoleHost:
		return "_INBOX_" + host
	case RoleAdmin:
		return "_INBOX"
	}
	return "_INBOX_" + string(r)
}

// Permissions returns the publish and subscribe allow lists of a user.
func Permissions(r Role, host string) (publish, subscribe []string, err error) {
	switch r {
	case RoleHost:
		if err := ValidHostID(host); err != nil {
			return nil, nil, err
		}
		var pub []string
		for _, k := range HostSubjects {
			pub = append(pub, "asm."+host+"."+k)
		}
		return pub, []string{InboxPrefix(r, host) + ".>"}, nil
	case RoleAdmin:
		return []string{"$JS.API.>", "$JS.ACK.>", "asm.>", "pwb.>"}, []string{"_INBOX.>", "asm.>", "pwb.>"}, nil
	case RoleInventory, RoleAlerter, RoleVerifier:
		pub := []string{jetStreamAPIInfo, streamInfoSubject}
		for _, c := range Consumers(r) {
			pub = append(pub,
				consumerAPIPrefix+"CREATE."+StreamName+"."+c,
				consumerAPIPrefix+"CREATE."+StreamName+"."+c+".>",
				consumerAPIPrefix+"DURABLE.CREATE."+StreamName+"."+c,
				consumerAPIPrefix+"INFO."+StreamName+"."+c,
				consumerAPIPrefix+"DELETE."+StreamName+"."+c,
				consumerAPIPrefix+"MSG.NEXT."+StreamName+"."+c,
				ackPrefix+c+".>",
			)
		}
		switch r {
		case RoleInventory:
			pub = append(pub, streamMsgGet, directGetPlain, directGetWildcard, cloudVerdicts, probeRequests)
		case RoleVerifier:
			pub = append(pub, verifierResults)
		}
		return pub, []string{InboxPrefix(r, "") + ".>"}, nil
	}
	return nil, nil, fmt.Errorf("unknown role %q", r)
}

// ValidHostID checks that a host id is one subject token (the agent's own rule).
func ValidHostID(host string) error {
	if host == "" || strings.ContainsAny(host, ".*> \t\r\n\"'\\{}[]#$") {
		return fmt.Errorf("host id %q is not a single plain subject token", host)
	}
	if reservedHostIDs[host] {
		return fmt.Errorf("host id %q is reserved (a service's reply inbox)", host)
	}
	return nil
}

// User is a minted user, as stored next to its seed in <name>.json.
type User struct {
	Name      string `json:"name"`
	Role      Role   `json:"role"`
	Host      string `json:"host,omitempty"`
	PublicKey string `json:"public_key"`
}

// UserName is "host-<id>" for a host and the role name for the others.
func UserName(r Role, host string) string {
	if r == RoleHost {
		return "host-" + host
	}
	return string(r)
}

// Mint creates an nkey user of role r in dir: <name>.nk holds the seed (mode 0600, give
// it to the service or host as --nats-nkey) and <name>.json the public part that Render
// reads. An existing seed is never overwritten.
func Mint(dir string, r Role, host string) (User, string, error) {
	if _, _, err := Permissions(r, host); err != nil {
		return User{}, "", err
	}
	if r != RoleHost {
		host = ""
	}
	name := UserName(r, host)
	seedPath := filepath.Join(dir, name+".nk")
	kp, err := nkeys.CreateUser()
	if err != nil {
		return User{}, "", err
	}
	seed, err := kp.Seed()
	if err != nil {
		return User{}, "", err
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return User{}, "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return User{}, "", err
	}
	f, err := os.OpenFile(seedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return User{}, "", fmt.Errorf("seed: %w", err)
	}
	if _, err := f.Write(append(seed, '\n')); err != nil {
		f.Close()
		return User{}, "", err
	}
	if err := f.Close(); err != nil {
		return User{}, "", err
	}
	u := User{Name: name, Role: r, Host: host, PublicKey: pub}
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return User{}, "", err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), append(b, '\n'), 0o644); err != nil {
		return User{}, "", err
	}
	return u, seedPath, nil
}

// Load reads every <name>.json in dir, sorted by name.
func Load(dir string) ([]User, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var users []User
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var u User
		if err := json.Unmarshal(b, &u); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if !nkeys.IsValidPublicUserKey(u.PublicKey) {
			return nil, fmt.Errorf("%s: %q is not an nkey user public key", p, u.PublicKey)
		}
		users = append(users, u)
	}
	if len(users) == 0 {
		return nil, errors.New("no users (*.json) in " + dir)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users, nil
}

// Render returns the nats-server authorization block for users, to include from the
// server config (`include "portwarden-users.conf"`).
func Render(users []User) (string, error) {
	var b strings.Builder
	b.WriteString("# Generated by portwarden-natsauth render. Do not edit: re-run it after minting.\n")
	b.WriteString("authorization {\n  users = [\n")
	for _, u := range users {
		pub, sub, err := Permissions(u.Role, u.Host)
		if err != nil {
			return "", fmt.Errorf("user %s: %w", u.Name, err)
		}
		if !nkeys.IsValidPublicUserKey(u.PublicKey) {
			return "", fmt.Errorf("user %s: bad public key", u.Name)
		}
		fmt.Fprintf(&b, "    # %s\n", u.Name)
		fmt.Fprintf(&b, "    {\n      nkey: %s\n      permissions: {\n", strconv.Quote(u.PublicKey))
		fmt.Fprintf(&b, "        publish: { allow: %s }\n", quoteList(pub))
		fmt.Fprintf(&b, "        subscribe: { allow: %s }\n", quoteList(sub))
		b.WriteString("      }\n    }\n")
	}
	b.WriteString("  ]\n}\n")
	return b.String(), nil
}

func quoteList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range slices.Clone(xs) {
		q[i] = strconv.Quote(x)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

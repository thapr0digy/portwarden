// portwarden-inventory keeps the current state of every host, listener, exposure and
// proxy route in PostgreSQL from the ASM_EVENTS stream, raises "host silent" when a
// host's heartbeats stop, runs the cloud look-up (level 3) and serves a read-only JSON
// API. Several instances may run: the one holding the database's leader lock consumes and
// runs the workers, the others wait as hot standbys that serve reads (README "Running a
// standby"). See README "Backend".
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"

	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/leader"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/cloud"
	cloudaws "github.com/thapr0digy/portwarden/internal/cloud/aws"
	cloudazure "github.com/thapr0digy/portwarden/internal/cloud/azure"
	cloudgcp "github.com/thapr0digy/portwarden/internal/cloud/gcp"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
	"github.com/thapr0digy/portwarden/internal/inventory"
	"github.com/thapr0digy/portwarden/internal/inventory/api"
	"github.com/thapr0digy/portwarden/internal/inventory/pg"
	"github.com/thapr0digy/portwarden/internal/natsauth"
	"github.com/thapr0digy/portwarden/internal/version"
)

// Config is the JSON config file (--config).
type Config struct {
	NATS svc.NATS `json:"nats"`
	// PostgresDSNFile holds the DSN (with its password); PORTWARDEN_INVENTORY_DSN wins.
	PostgresDSNFile string `json:"postgres_dsn_file"`
	// Listen is the API address; loopback by default. The API has no TLS of its own, so a
	// non-loopback address (bearer token in cleartext) is refused unless
	// AllowInsecureListen is set (e.g. behind a TLS-terminating proxy on the same host).
	Listen              string `json:"listen"`
	AllowInsecureListen bool   `json:"allow_insecure_listen"`
	// TokenFile holds the API bearer token; PORTWARDEN_INVENTORY_TOKEN wins.
	TokenFile string `json:"token_file"`
	// API holds the admin token (M8: forgetting hosts); without one, forgetting is off.
	API APIConfig `json:"api"`
	// SilentAfter: a host without a heartbeat this long is silent (default 90s).
	SilentAfter svc.Duration `json:"silent_after"`
	Cloud       CloudConfig  `json:"cloud"`
	// Reprobe: listeners at level bound or above whose last outside probe is older than
	// this are requested again (default 24h).
	Reprobe   svc.Duration    `json:"reprobe"`
	Retention RetentionConfig `json:"retention"`
	// Leader tunes the standby's poll and the leader's lock check (README "Running a
	// standby").
	Leader svc.Leader `json:"leader"`
}

// APIConfig configures the API's admin side.
type APIConfig struct {
	// AdminTokenFile holds the token DELETE /v1/hosts/{id} needs (not the read token);
	// PORTWARDEN_INVENTORY_ADMIN_TOKEN wins. Unset: forgetting hosts is disabled (403).
	AdminTokenFile string `json:"admin_token_file"`
}

// RetentionConfig prunes old rows (M8). History and Quarantine are ages; unset or null
// means the default (90 days, 30 days), "0s" keeps the table forever; a negative duration
// is refused when the config is read. Interval (unset: 1h) must be at least a minute,
// Batch (unset: 1000) 1 to 10 000.
type RetentionConfig struct {
	History    *svc.Duration `json:"history"`
	Quarantine *svc.Duration `json:"quarantine"`
	// Interval between passes (default 1h); Batch rows per DELETE (default 1000).
	Interval svc.Duration `json:"interval"`
	Batch    int          `json:"batch"`
}

func (r RetentionConfig) validate() error {
	if r.Interval != 0 && time.Duration(r.Interval) < time.Minute {
		return errors.New("retention.interval must be at least 1m")
	}
	if r.Batch < 0 || r.Batch > 10000 {
		return errors.New("retention.batch must be 1 to 10000")
	}
	return nil
}

func (c Config) retention() inventory.Retention {
	age := func(d *svc.Duration, def time.Duration) time.Duration {
		if d == nil {
			return def
		}
		return time.Duration(*d)
	}
	r := c.Retention
	return inventory.Retention{History: age(r.History, inventory.DefaultHistoryRetention),
		Quarantine: age(r.Quarantine, inventory.DefaultQuarantineRetention), Interval: time.Duration(r.Interval), Batch: r.Batch}.WithDefaults()
}

const defaultListen = "127.0.0.1:8740"

// adminToken returns the admin token ("" when none is configured).
func adminToken(cfg Config) (string, error) {
	if os.Getenv(adminTokenEnv) == "" && cfg.API.AdminTokenFile == "" {
		return "", nil
	}
	return svc.Secret(adminTokenEnv, cfg.API.AdminTokenFile)
}

const adminTokenEnv = "PORTWARDEN_INVENTORY_ADMIN_TOKEN"

// CloudConfig turns on the level 3 look-up.
type CloudConfig struct {
	// AWS enables the AWS look-up with the SDK's default credentials (instance role,
	// environment, shared config). Hosts of a cloud not enabled get "unsupported".
	AWS      bool         `json:"aws"`
	Refresh  svc.Duration `json:"refresh"`
	Endpoint string       `json:"endpoint"`
	// Regions, when set, are the only regions looked up.
	Regions []string `json:"regions"`
	// VPNCIDRs are the operator's VPN egress or office ranges (M10). The reach rule counts
	// every source address a cloud rule allows as the internet unless it is private
	// (RFC 1918, CGNAT, ULA and the other special-purpose ranges) or listed here.
	VPNCIDRs []string `json:"vpn_cidrs"`
	// AllowBroad accepts vpn_cidrs wider than /8 (IPv4) or /16 (IPv6); a /0 is never
	// accepted.
	AllowBroad bool `json:"allow_broad"`
	// GCP enables the GCP look-up (M10 phase 2).
	GCP GCPConfig `json:"gcp"`
	// Azure enables the Azure look-up (M10 phase 3).
	Azure AzureConfig `json:"azure"`
}

// AzureConfig is cloud.azure. The ARM, login and IMDS endpoints are fixed (public Azure);
// none is configurable. The credential is the client secret when client_secret_file is
// set, else the federated token when federated_token_file (or AZURE_FEDERATED_TOKEN_FILE)
// is set, else the managed identity of the Azure VM the inventory runs on.
type AzureConfig struct {
	Enabled bool `json:"enabled"`
	// Subscriptions are the only subscriptions looked up (required when enabled).
	Subscriptions []string `json:"subscriptions"`
	// TenantID and ClientID name the app registration (AZURE_TENANT_ID and
	// AZURE_CLIENT_ID when empty); with a managed identity ClientID picks a user-assigned
	// one.
	TenantID string `json:"tenant_id"`
	ClientID string `json:"client_id"`
	// ClientSecretFile holds the app's client secret (a systemd credential).
	ClientSecretFile string `json:"client_secret_file"`
	// FederatedTokenFile holds a federated (OIDC) token, re-read at every exchange.
	FederatedTokenFile string `json:"federated_token_file"`
}

// options resolves the environment fallbacks (what AKS workload identity injects).
func (a AzureConfig) options(policy reach.Policy, getenv func(string) string) cloudazure.Options {
	o := cloudazure.Options{TenantID: a.TenantID, ClientID: a.ClientID, ClientSecretFile: a.ClientSecretFile,
		FederatedTokenFile: a.FederatedTokenFile, Subscriptions: a.Subscriptions, Policy: policy}
	if o.ClientSecretFile == "" && o.FederatedTokenFile == "" {
		o.FederatedTokenFile = getenv("AZURE_FEDERATED_TOKEN_FILE")
	}
	if o.FederatedTokenFile != "" || o.ClientSecretFile != "" {
		if o.TenantID == "" {
			o.TenantID = getenv("AZURE_TENANT_ID")
		}
	}
	if o.ClientID == "" && (o.FederatedTokenFile != "" || o.ClientSecretFile != "") {
		o.ClientID = getenv("AZURE_CLIENT_ID")
	}
	return o
}

// GCPConfig is cloud.gcp. The API, token and metadata endpoints are fixed; none is
// configurable.
type GCPConfig struct {
	Enabled bool `json:"enabled"`
	// KeyFile is a service-account JSON key (a systemd credential). Empty: the
	// GOOGLE_APPLICATION_CREDENTIALS file when set, else the metadata server of the GCE
	// machine the inventory runs on.
	KeyFile string `json:"key_file"`
	// Projects are the only projects looked up (required when enabled).
	Projects []string `json:"projects"`
	// HierarchyConfirmed tells the look-up that a getEffectiveFirewalls answer without
	// hierarchical policies means there are none (the projects are outside an
	// organisation, or the role can read the organisation's and folders' policies).
	// Google does not document whether policies the caller cannot read are left out, so
	// without it a closed interface with no hierarchical policy is undetermined.
	HierarchyConfirmed bool `json:"hierarchy_confirmed"`
}

// keyFile resolves the service-account key file ("" for the metadata server).
func (g GCPConfig) keyFile(getenv func(string) string) string {
	if g.KeyFile != "" {
		return g.KeyFile
	}
	return getenv("GOOGLE_APPLICATION_CREDENTIALS")
}

// providers builds the enabled cloud providers; none enabled is an empty map.
func (c CloudConfig) providers(ctx context.Context, policy reach.Policy, getenv func(string) string) (map[string]cloud.Provider, []string, error) {
	provs := map[string]cloud.Provider{}
	var names []string
	if c.AWS {
		prov, err := cloudaws.New(ctx, cloudaws.Options{Endpoint: c.Endpoint, Regions: c.Regions, Policy: policy})
		if err != nil {
			return nil, nil, err
		}
		provs["aws"] = prov
		names = append(names, "aws")
	}
	if c.GCP.Enabled {
		prov, err := cloudgcp.New(cloudgcp.Options{KeyFile: c.GCP.keyFile(getenv), Projects: c.GCP.Projects, Policy: policy, HierarchyConfirmed: c.GCP.HierarchyConfirmed})
		if err != nil {
			return nil, nil, fmt.Errorf("cloud.%w", err)
		}
		provs["gcp"] = prov
		names = append(names, "gcp ("+prov.Credential+", projects "+strings.Join(c.GCP.Projects, ",")+")")
	}
	if c.Azure.Enabled {
		prov, err := cloudazure.New(c.Azure.options(policy, getenv))
		if err != nil {
			return nil, nil, fmt.Errorf("cloud.%w", err)
		}
		provs["azure"] = prov
		names = append(names, "azure ("+prov.Credential+", subscriptions "+strings.Join(c.Azure.Subscriptions, ",")+")")
	}
	return provs, names, nil
}

// policy parses vpn_cidrs into the reach rule; a bad, /0 or (without allow_broad) too
// broad range is refused at start, and the accepted ranges are logged.
func (c CloudConfig) policy() (reach.Policy, error) {
	vpn, err := reach.ParseVPN(c.VPNCIDRs, c.AllowBroad)
	if err != nil {
		return reach.Policy{}, fmt.Errorf("cloud.%w", err)
	}
	pol := reach.NewPolicy(vpn)
	ranges := make([]string, 0, len(vpn))
	for _, p := range pol.VPN() {
		ranges = append(ranges, p.String())
	}
	slog.Info("cloud: reach rule: sources outside private ranges and vpn_cidrs count as the internet", "vpn_cidrs", ranges, "allow_broad", c.AllowBroad)
	return pol, nil
}

func main() {
	version.HandleFlag()
	if len(os.Args) > 1 && os.Args[1] == "forget-host" {
		if err := forgetHost(os.Args[2:], os.Stdout, os.Getenv); err != nil {
			fmt.Fprintln(os.Stderr, "portwarden-inventory forget-host:", err)
			os.Exit(1)
		}
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	path := flag.String("config", "/etc/portwarden/inventory.json", "config file (JSON)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	err := run(ctx, *path, openStore)
	stop()
	os.Exit(exitCode(err))
}

// exitCode is the process's exit status for run's result: 0 for a clean stop (nil, or the
// signal's context.Canceled), else 1 after logging the error.
func exitCode(err error) int {
	if err == nil || errors.Is(err, context.Canceled) {
		return 0
	}
	slog.Error("portwarden-inventory", "err", err)
	return 1
}

// invStore is what run uses of the PostgreSQL store; tests pass an in-memory one.
type invStore interface {
	inventory.Store
	inventory.Reader
	inventory.CloudState
	inventory.ProbeState
	inventory.Pruner
	Quarantine(ctx context.Context, streamSeq uint64, subject, why string, data []byte) error
	// Elect waits as a standby until this instance leads (state shows the role), then
	// fences the store's writes with the lease.
	Elect(ctx context.Context, cfg svc.Leader, state *leader.State) (leader.Lease, error)
	Close()
}

var _ invStore = (*pg.Store)(nil)

// openStoreFunc opens the state database at dsn.
type openStoreFunc func(ctx context.Context, dsn string) (invStore, error)

// openStore is the store main uses (tests running main in a child process replace it).
var openStore openStoreFunc = openPG

func openPG(ctx context.Context, dsn string) (invStore, error) {
	s, err := pg.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// settings is the config after loading and checking, with its secrets read.
type settings struct {
	cfg        Config
	policy     reach.Policy
	dsn, token string
}

// load reads and checks the config and reads the DSN and API token, in this order (the
// first problem is the one reported). The admin token is read later, by run, as before.
func load(path string) (settings, error) {
	var cfg Config
	if err := svc.Load(path, &cfg); err != nil {
		return settings{}, err
	}
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if err := cfg.Retention.validate(); err != nil {
		return settings{}, err
	}
	if err := cfg.Leader.Validate(); err != nil {
		return settings{}, err
	}
	policy, err := cfg.Cloud.policy()
	if err != nil {
		return settings{}, err
	}
	if err := checkListen(cfg.Listen, cfg.AllowInsecureListen); err != nil {
		return settings{}, err
	}
	dsn, err := svc.Secret("PORTWARDEN_INVENTORY_DSN", cfg.PostgresDSNFile)
	if err != nil {
		return settings{}, fmt.Errorf("postgres dsn: %w", err)
	}
	token, err := svc.Secret("PORTWARDEN_INVENTORY_TOKEN", cfg.TokenFile)
	if err != nil {
		return settings{}, fmt.Errorf("api token: %w", err)
	}
	return settings{cfg: cfg, policy: policy, dsn: dsn, token: token}, nil
}

// run loads the config, opens the store with openStore and serves the API (reads on a
// standby too), waits as a standby until this instance leads, then consumes the stream
// until ctx ends (then it returns ctx's error), the API server fails, or the lead is lost
// (an error: the process exits 1 and systemd restarts it as a standby).
func run(ctx context.Context, path string, openStore openStoreFunc) error {
	st, err := load(path)
	if err != nil {
		return err
	}
	cfg, token := st.cfg, st.token
	ctx, stop := context.WithCancel(ctx)
	defer stop()

	store, err := openStore(ctx, st.dsn)
	if err != nil {
		return err
	}
	defer store.Close()

	silentAfter := cfg.SilentAfter.D(90 * time.Second)
	cons := &inventory.Consumer{Store: store, Liveness: liveness.New(silentAfter), Feed: liveness.NewFeed(silentAfter, time.Now())}
	var role leader.State
	apiSrv, err := api.New(store, token)
	if err != nil {
		return err
	}
	apiSrv.SetRole(&role)
	if admin, err := adminToken(cfg); err != nil {
		return fmt.Errorf("api admin token: %w", err)
	} else if admin == "" {
		slog.Warn("forgetting hosts is disabled: no api.admin_token_file (DELETE /v1/hosts/{id} answers 403)")
	} else if err := apiSrv.SetForget(admin, cons.Forget); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: apiSrv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		slog.Info("api listening", "addr", ln.Addr().String())
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("api server", "err", err)
			stop()
		}
	}()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()
	lease, err := store.Elect(ctx, cfg.Leader, &role)
	if err != nil {
		return err
	}
	return lead(ctx, st, store, cons, lease)
}

// lead does the leader's work until ctx ends or the lease is lost. Its workers stop
// before the lock is released, so the next leader never overlaps them.
func lead(ctx context.Context, st settings, store invStore, cons *inventory.Consumer, lease leader.Lease) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-lease.Lost():
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rcancel()
		if lerr := lease.Err(); lerr != nil {
			_ = lease.Release(rctx)
			err = fmt.Errorf("lost leadership: %w", lerr)
			return
		}
		if rerr := lease.Release(rctx); rerr != nil {
			slog.Warn("releasing the leader lock failed (it is freed when the session closes)", "err", rerr)
		}
	}()
	return work(ctx, st, store, cons)
}

// work is one leader's run: NATS, the stream, the workers and the consumer, until ctx
// ends.
func work(ctx context.Context, st settings, store invStore, cons *inventory.Consumer) error {
	cfg, policy := st.cfg, st.policy
	// Connect retries in the background.
	nc, js, err := bus.Connect(cfg.NATS.Bus(natsauth.RoleInventory, "portwarden-inventory", cons.SetConnected))
	if err != nil {
		return err
	}
	defer nc.Close()
	pub := bus.NewPublisher(js, "inventory")
	cons.Announce = func(ctx context.Context, host string) (uint64, error) {
		id := bus.NewEventID()
		return pub.PublishSeq(ctx, bus.ForgottenSubject(host), id, &asmv1.HostForgotten{EventId: id, HostId: host, At: timestamppb.Now()})
	}
	stream, err := svc.WaitStream(ctx, js)
	if err != nil {
		return err
	}
	cons.Snapshots = inventory.StreamSnapshots{Stream: stream}
	info, err := stream.Info(ctx)
	if err != nil {
		return fmt.Errorf("stream info: %w", err)
	}
	// Forget marks belong to one stream: a recreated stream starts its sequences over.
	if n, err := store.PruneMarks(ctx, info.Created, info.State.LastSeq); err != nil {
		return fmt.Errorf("forget marks: %w", err)
	} else if n > 0 {
		slog.Warn("dropped forget marks of another stream (or past its last sequence)", "marks", n, "stream_created", info.Created)
	}
	cons.SetStream(info.Created)
	if err := cons.SeedLiveness(ctx); err != nil {
		return err
	}
	// Background workers stop before the store closes (deferred above).
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	probes := inventory.NewProbeRequester(store, pub.Publish)
	probes.Reprobe = cfg.Reprobe.D(24 * time.Hour)
	cons.Exposed = probes.Notify
	wg.Go(func() { probes.Run(ctx) })
	ret := cfg.retention()
	slog.Info("retention", "history", ret.History.String(), "quarantine", ret.Quarantine.String(), "interval", ret.Interval.String(), "batch", ret.Batch)
	wg.Go(func() { ret.Run(ctx, store) })
	provs, names, err := cfg.Cloud.providers(ctx, policy, os.Getenv)
	if err != nil {
		return err
	}
	if len(provs) > 0 {
		cpub := bus.NewPublisher(js, "cloud")
		lookup := inventory.NewCloudLookup(store, provs, cpub.Publish, cpub.RunID)
		lookup.Refresh = cfg.Cloud.Refresh.D(10 * time.Minute)
		cons.Changed = lookup.Notify
		wg.Go(func() { lookup.Run(ctx) })
		slog.Info("cloud look-up on", "providers", strings.Join(names, "; ")+" (others: unsupported)", "refresh", lookup.Refresh.String())
	}
	wg.Go(func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := cons.CheckSilence(ctx); err != nil {
					slog.Warn("silence check", "err", err)
				}
			}
		}
	})

	c, err := bus.Durable(ctx, js, natsauth.ConsumerInventory, bus.DurableOptions{
		// Its own announcements too: a forget whose database step failed heals here.
		Filters: []string{"asm.>", "pwb.cloud.*.exposure", "pwb.verifier.*.exposure", "pwb.inventory.*.forgotten"}})
	if err != nil {
		return err
	}
	slog.Info("consuming", "stream", natsauth.StreamName, "consumer", natsauth.ConsumerInventory)
	return svc.Consume(ctx, c, func(ctx context.Context, m jetstream.Msg) error {
		meta := inventory.Meta{}
		if md, err := m.Metadata(); err == nil {
			meta.StreamSeq, meta.StreamTime = md.Sequence.Stream, md.Timestamp
		}
		return cons.Handle(ctx, m.Subject(), m.Data(), meta)
	}, svc.ConsumeOptions{Quarantine: func(ctx context.Context, m jetstream.Msg, why error) error {
		var seq uint64
		if md, err := m.Metadata(); err == nil {
			seq = md.Sequence.Stream
		}
		return store.Quarantine(ctx, seq, m.Subject(), why.Error(), m.Data())
	}})
}

// checkListen refuses a non-loopback API address without TLS unless allowed.
func checkListen(addr string, allowInsecure bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if ip, err := netip.ParseAddr(host); (err == nil && ip.IsLoopback()) || host == "localhost" || allowInsecure {
		return nil
	}
	return fmt.Errorf("listen %s is not loopback and the API has no TLS: the bearer token would cross the network in cleartext (set allow_insecure_listen to accept that)", addr)
}

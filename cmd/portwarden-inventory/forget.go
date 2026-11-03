package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

const forgetUsage = `usage: portwarden-inventory forget-host [--config FILE] [--url URL] [--token-file FILE] <host-id>

Forgets a decommissioned host through the running inventory's API (DELETE /v1/hosts/<id>):
its listeners, proxies and exposure history are removed, the alerter drops its silence,
tamper and dedupe marks, and it stops paging host_silent. Stop the host's agent first: a
host that sends again afterwards is a new host. The API address and token come from the
service's config (listen, token_file); PORTWARDEN_INVENTORY_TOKEN wins over the file.`

// forgetHost runs the forget-host subcommand.
func forgetHost(args []string, stdout io.Writer, getenv func(string) string) error {
	fs := flag.NewFlagSet("forget-host", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "/etc/portwarden/inventory.json", "the inventory's config file")
	base := fs.String("url", "", "the API's base URL (default: from the config's listen)")
	tokenFile := fs.String("token-file", "", "the API token file (default: the config's token_file)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n%s", err, forgetUsage)
	}
	if fs.NArg() != 1 {
		return errors.New("one host id is required\n" + forgetUsage)
	}
	host := fs.Arg(0)
	if err := natsauth.ValidHostID(host); err != nil {
		return err
	}
	token := strings.TrimSpace(getenv("PORTWARDEN_INVENTORY_TOKEN"))
	if *base == "" || (token == "" && *tokenFile == "") {
		var cfg Config
		if err := loadConfig(*cfgPath, &cfg); err != nil {
			return err
		}
		if *base == "" {
			*base = apiBase(cfg.Listen)
		}
		if *tokenFile == "" {
			*tokenFile = cfg.TokenFile
		}
	}
	if token == "" {
		if *tokenFile == "" {
			return errors.New("no API token: set PORTWARDEN_INVENTORY_TOKEN, --token-file or the config's token_file")
		}
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("api token: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimRight(*base, "/")+"/v1/hosts/"+url.PathEscape(host), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s: %s", resp.Status, e.Error)
		}
		return errors.New(resp.Status)
	}
	_, err = fmt.Fprintln(stdout, strings.TrimSpace(string(body)))
	return err
}

// apiBase turns the config's listen address into a URL to reach it locally.
func apiBase(listen string) string {
	if listen == "" {
		listen = defaultListen
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func loadConfig(path string, cfg *Config) error { return svc.Load(path, cfg) }

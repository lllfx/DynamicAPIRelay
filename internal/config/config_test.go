package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/config"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

const secret = "0123456789abcdef0123456789abcdef" // 32 bytes

func TestLoadDefaults(t *testing.T) {
	c, err := config.Load(env(map[string]string{"RELAY_KEYS": "alice:" + secret}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != "127.0.0.1:8080" || c.MaxRequestBytes != 104857600 || c.MaxResponseBytes != 0 ||
		c.RatePerSec != 30 || c.RateBurst != 30 || c.MaxConcurrent != 20 ||
		c.DialTimeout != 10*time.Second || c.TLSHandshakeTimeout != 10*time.Second ||
		c.ResponseHeaderTimeout != 60*time.Second || c.IdleConnTimeout != 90*time.Second ||
		c.MaxRequestDuration != 0 || c.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if c.Keys["alice"] != secret || len(c.Keys) != 1 {
		t.Errorf("keys: %v", c.Keys)
	}
}

func TestLoadOverrides(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"RELAY_KEYS": "a:" + secret + ",b:" + secret + "x", "RELAY_LISTEN_ADDR": ":9000",
		"RELAY_MAX_CONCURRENT": "5", "RELAY_RESPONSE_HEADER_TIMEOUT": "2m", "RELAY_RATE_PER_SEC": "1.5",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":9000" || c.MaxConcurrent != 5 || c.ResponseHeaderTimeout != 2*time.Minute ||
		c.RatePerSec != 1.5 || len(c.Keys) != 2 {
		t.Errorf("overrides not applied: %+v", c)
	}
}

func TestLoadRejectsKeys(t *testing.T) {
	for name, keys := range map[string]string{
		"missing":   "",
		"short":     "alice:short",
		"noColon":   secret,
		"badID":     "al ice:" + secret,
		"dupID":     "a:" + secret + ",a:" + secret + "x",
		"dupSecret": "a:" + secret + ",b:" + secret,
	} {
		_, err := config.Load(env(map[string]string{"RELAY_KEYS": keys}))
		if err == nil {
			t.Errorf("%s: expected error", name)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "short") && name == "short" {
			t.Errorf("%s: error leaks secret: %v", name, err)
		}
	}
}

func TestLoadRejectsBadNumbers(t *testing.T) {
	for k, v := range map[string]string{
		"RELAY_MAX_CONCURRENT": "0", "RELAY_DIAL_TIMEOUT": "abc", "RELAY_RATE_PER_SEC": "-1",
		"RELAY_MAX_REQUEST_BYTES": "0", "RELAY_MAX_RESPONSE_BYTES": "-5", "RELAY_IDLE_CONN_TIMEOUT": "-1s",
	} {
		if _, err := config.Load(env(map[string]string{"RELAY_KEYS": "a:" + secret, k: v})); err == nil {
			t.Errorf("%s=%s: expected error", k, v)
		}
	}
}

func TestLoadDashboardDefaults(t *testing.T) {
	c, err := config.Load(env(map[string]string{"RELAY_KEYS": "a:" + secret}))
	if err != nil {
		t.Fatal(err)
	}
	if c.StatsDB != "./data/relay-stats.db" || c.StatsRetentionDays != 30 || c.DashboardAddr != "127.0.0.1:8081" ||
		c.DashboardPassword != "" || c.DashboardLocation == nil || c.DashboardLocation.String() != "Asia/Shanghai" ||
		strings.Join(c.TrustedProxies, ",") != "127.0.0.1/32,::1/128" {
		t.Fatalf("defaults %+v", c)
	}
}

func TestLoadDashboardDisabled(t *testing.T) {
	c, err := config.Load(env(map[string]string{"RELAY_KEYS": "a:" + secret, "RELAY_DASHBOARD_ADDR": ""}))
	if err != nil || c.DashboardAddr != "" {
		t.Fatalf("addr %q err %v", c.DashboardAddr, err)
	}
}

func TestLoadRejectsPublicDashboardWithoutPassword(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8081", ":8081", "10.0.0.5:8081", "example.com:8081"} {
		if _, err := config.Load(env(map[string]string{"RELAY_KEYS": "a:" + secret, "RELAY_DASHBOARD_ADDR": addr})); err == nil {
			t.Errorf("%s without password: expected error", addr)
		}
	}
	if _, err := config.Load(env(map[string]string{"RELAY_KEYS": "a:" + secret, "RELAY_DASHBOARD_ADDR": "0.0.0.0:8081",
		"RELAY_DASHBOARD_PASSWORD": "pw"})); err != nil {
		t.Errorf("public with password: %v", err)
	}
	for _, addr := range []string{"localhost:8081", "[::1]:8081", "127.0.0.2:8081"} {
		if _, err := config.Load(env(map[string]string{"RELAY_KEYS": "a:" + secret, "RELAY_DASHBOARD_ADDR": addr})); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestLoadRejectsBadDashboardValues(t *testing.T) {
	for k, v := range map[string]string{
		"RELAY_DASHBOARD_TZ": "Mars/Base", "RELAY_TRUSTED_PROXIES": "notacidr", "RELAY_STATS_RETENTION_DAYS": "0",
		"RELAY_DASHBOARD_ADDR": "nonsense",
	} {
		if _, err := config.Load(env(map[string]string{"RELAY_KEYS": "a:" + secret, k: v})); err == nil {
			t.Errorf("%s=%s: expected error", k, v)
		}
	}
	c, err := config.Load(env(map[string]string{"RELAY_KEYS": "a:" + secret, "RELAY_TRUSTED_PROXIES": " 10.0.0.0/8 , ::1/128 "}))
	if err != nil || strings.Join(c.TrustedProxies, ",") != "10.0.0.0/8,::1/128" {
		t.Errorf("proxies %v err %v", c.TrustedProxies, err)
	}
}

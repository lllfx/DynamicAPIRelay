// Command relay runs the DynamicAPIRelay HTTPS API relay and its usage dashboard.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
	_ "time/tzdata" // dashboard time zone works on hosts without tzdata

	"github.com/lllfx/DynamicAPIRelay/internal/auth"
	"github.com/lllfx/DynamicAPIRelay/internal/config"
	"github.com/lllfx/DynamicAPIRelay/internal/dashboard"
	"github.com/lllfx/DynamicAPIRelay/internal/limiter"
	"github.com/lllfx/DynamicAPIRelay/internal/policy"
	"github.com/lllfx/DynamicAPIRelay/internal/relay"
	"github.com/lllfx/DynamicAPIRelay/internal/server"
	"github.com/lllfx/DynamicAPIRelay/internal/stats"
	"github.com/lllfx/DynamicAPIRelay/internal/transport"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "relay:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	store, err := stats.Open(cfg.StatsDB)
	if err != nil {
		return err
	}
	defer store.Close()
	recorder := stats.NewRecorder(store, logger, stats.RecorderOptions{QueueSize: 10000, BatchSize: 200, FlushInterval: time.Second})
	retentionCtx, stopRetention := context.WithCancel(context.Background())
	defer stopRetention()
	go stats.RunRetention(retentionCtx, store, time.Duration(cfg.StatsRetentionDays)*24*time.Hour, 24*time.Hour, time.Now, logger)

	relayHandler := relay.New(relay.Options{
		Transport: transport.New(transport.Options{
			DialTimeout:           cfg.DialTimeout,
			TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
			ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
			IdleConnTimeout:       cfg.IdleConnTimeout,
		}),
		Policy:             policy.Default(),
		MaxRequestBytes:    cfg.MaxRequestBytes,
		MaxResponseBytes:   cfg.MaxResponseBytes,
		MaxRequestDuration: cfg.MaxRequestDuration,
		Logger:             logger,
	})
	router, err := server.NewRouter(server.Deps{
		Auth:           auth.NewKeyStore(cfg.Keys),
		Limiter:        limiter.New(cfg.RatePerSec, cfg.RateBurst, cfg.MaxConcurrent),
		Relay:          relayHandler,
		Logger:         logger,
		Recorder:       recorder,
		TrustedProxies: cfg.TrustedProxies,
	})
	if err != nil {
		return err
	}
	// No ReadTimeout/WriteTimeout: they would cut off SSE streams and large transfers.
	relaySrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		MaxHeaderBytes:    64 << 10,
		IdleTimeout:       120 * time.Second,
	}

	errc := make(chan error, 2)
	serve := func(name string, s *http.Server) {
		logger.Info("listening", "server", name, "addr", s.Addr)
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("%s server: %w", name, err)
		}
	}
	go serve("relay", relaySrv)

	var dashSrv *http.Server
	if cfg.DashboardAddr != "" {
		keyIDs := make([]string, 0, len(cfg.Keys))
		for id := range cfg.Keys {
			keyIDs = append(keyIDs, id)
		}
		sort.Strings(keyIDs)
		dashSrv = &http.Server{
			Addr: cfg.DashboardAddr,
			Handler: dashboard.New(dashboard.Options{
				Store: store, Dropped: recorder.Dropped, KeyIDs: keyIDs, Location: cfg.DashboardLocation,
				Password: cfg.DashboardPassword, RetentionDays: cfg.StatsRetentionDays, Logger: logger,
			}),
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      30 * time.Second,
		}
		go serve("dashboard", dashSrv)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigc:
		logger.Info("shutting down", "signal", sig.String())
	case err = <-errc:
		logger.Error("server failed", "error", err)
	}

	shutdown := func(s *http.Server, d time.Duration) {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			logger.Warn("shutdown incomplete", "addr", s.Addr, "error", err)
		}
	}
	shutdown(relaySrv, 30*time.Second)
	if dashSrv != nil {
		shutdown(dashSrv, 5*time.Second)
	}
	stopRetention()
	flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ferr := recorder.Close(flushCtx); ferr != nil {
		logger.Warn("stats flush incomplete", "error", ferr)
	}
	return err
}

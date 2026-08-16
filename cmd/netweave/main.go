package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/benzhi/netweave/internal/domain"
	"github.com/benzhi/netweave/internal/httpapp"
)

const projectVersion = "0.1.0"

func main() {
	command := flag.String("command", "serve", "operation: serve, export, verify, snapshot, or inspect")
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	dataDir := flag.String("data", "./data", "durable local data directory")
	incidentID := flag.String("incident", "", "incident ID for export")
	output := flag.String("output", "", "output file for export or snapshot")
	version := flag.Bool("version", false, "print NetWeave version")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "NetWeave %s - local incident net operations\n\n", projectVersion)
		fmt.Fprintln(flag.CommandLine.Output(), "Usage:")
		fmt.Fprintln(flag.CommandLine.Output(), "  netweave [flags]")
		fmt.Fprintln(flag.CommandLine.Output(), "\nThe default command starts the server. Administrative commands use the same durable journal.")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *version {
		fmt.Println(projectVersion)
		return
	}

	journalPath := filepath.Join(*dataDir, "journal.jsonl")
	store, err := domain.NewStore(journalPath)
	if err != nil {
		fatal(err)
	}
	defer store.Close()

	switch *command {
	case "serve":
		if err := runServer(store, *listen); err != nil {
			fatal(err)
		}
	case "export":
		if *incidentID == "" {
			fatal(errors.New("--incident is required for export"))
		}
		data, err := store.Export(*incidentID)
		if err != nil {
			fatal(err)
		}
		if *output == "" {
			_, _ = os.Stdout.Write(append(data, '\n'))
			return
		}
		if err := os.WriteFile(*output, append(data, '\n'), 0600); err != nil {
			fatal(err)
		}
	case "verify":
		report, err := store.Verify()
		if err != nil {
			fatal(err)
		}
		writeJSON(os.Stdout, report)
	case "snapshot":
		path := *output
		if path == "" {
			path = filepath.Join(*dataDir, "snapshot.json")
		}
		if err := store.SaveSnapshot(path); err != nil {
			fatal(err)
		}
		fmt.Printf("snapshot written to %s\n", path)
	case "inspect":
		incident, err := store.CurrentIncident()
		if errors.Is(err, domain.ErrNotFound) {
			writeJSON(os.Stdout, map[string]any{"incidents": 0, "journal": store.Journal().Head()})
			return
		}
		if err != nil {
			fatal(err)
		}
		summary, _ := store.Summary(incident.ID)
		writeJSON(os.Stdout, map[string]any{"incident": incident.ID, "status": incident.Status, "version": incident.Version, "summary": summary, "journal": store.Journal().Head()})
	default:
		fatal(fmt.Errorf("unknown command %q", *command))
	}
}

func runServer(store *domain.Store, address string) error {
	server, app := httpapp.NewServer(store, address)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, context.Canceled) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, syscall.EINVAL) {
			return nil
		}
		return err
	case <-ctx.Done():
		app.SetReady(false)
		app.Stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func writeJSON(w io.Writer, value any) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "netweave:", err)
	os.Exit(1)
}

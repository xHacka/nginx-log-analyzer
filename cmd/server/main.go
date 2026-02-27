package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/xHacka/nginx-log-analyzer/internal/config"
	"github.com/xHacka/nginx-log-analyzer/internal/handlers"
	"github.com/xHacka/nginx-log-analyzer/internal/ingest"
	"github.com/xHacka/nginx-log-analyzer/internal/repository"
	"html/template"
)

func main() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	sqliteRepo, err := repository.NewSQLite(cfg.DBPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer sqliteRepo.Close()
	var repo repository.LogRepository = sqliteRepo
	rules := ingest.NewFilterRules(
		cfg.Ignore.WhitelistedIPs,
		cfg.Ignore.SkipExtensions,
		cfg.Ignore.SkipMethods,
		cfg.Ignore.SkipStatusCodes,
		cfg.Ignore.SkipPathPrefixes,
	)

	funcMap := template.FuncMap{
		"formatTime": func(t float64) string {
			return time.Unix(int64(t), 0).Format("2006-01-02 15:04:05")
		},
		"statusClass": func(status int) string {
			switch {
			case status < 300:
				return "is-success"
			case status < 400:
				return "is-info"
			case status < 500:
				return "is-warning"
			default:
				return "is-danger"
			}
		},
	}

	parseTmpl := func(page string) *template.Template {
		t, err := template.New("").Funcs(funcMap).ParseFiles("web/templates/base.html", "web/templates/"+page)
		if err != nil {
			log.Fatalf("templates (%s): %v", page, err)
		}
		return t
	}
	tmplDashboard := parseTmpl("dashboard.html")
	tmplQuery := parseTmpl("query.html")

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	dh := &handlers.DashboardHandler{Repo: repo, Template: tmplDashboard}
	qh := &handlers.QueryHandler{Repo: repo, Template: tmplQuery}
	uh := &handlers.UploadHandler{Repo: repo, Rules: rules}
	r.Get("/", dh.ServeHTTP)
	r.Get("/query", qh.ServeHTTP)
	r.Post("/upload", uh.ServeHTTP)
	r.Get("/upload", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/static/upload.html")
	})

	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	// Retention job
	stopRetention := make(chan struct{})
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-stopRetention:
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-time.Duration(cfg.RetentionDays) * 24 * time.Hour)
				if err := repo.DeleteOlderThan(cutoff); err != nil {
					log.Printf("retention: %v", err)
				} else {
					log.Printf("retention: deleted entries older than %v", cutoff)
				}
			}
		}
	}()

	// Local file tailing
	if cfg.LogPath != "" {
		stopTail := make(chan struct{})
		go func() {
			if err := ingest.ReadFullFileAndTail(cfg.LogPath, repo, rules, stopTail); err != nil {
				log.Printf("tail: %v", err)
			}
		}()
		defer close(stopTail)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(stopRetention)
	}()

	log.Printf("Listening on %s", cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, r); err != nil {
		log.Fatalf("server: %v", err)
	}
}

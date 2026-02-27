package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"github.com/xHacka/nginx-log-analyzer/internal/repository"
)

type DashboardHandler struct {
	Repo          repository.LogRepository
	Template      *template.Template
	UploadEnabled bool
}

type DashboardPageData struct {
	PageID        string
	UploadEnabled bool
	*repository.DashboardStats
	RequestsByHourJSON   string
	StatusDistJSON       string
	TopCountriesJSON     string
	TopPathsJSON         string
}

func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour)
	stats, err := h.Repo.GetDashboardStats(since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	j1, _ := json.Marshal(stats.RequestsByHour)
	j2, _ := json.Marshal(stats.StatusDistribution)
	j3, _ := json.Marshal(stats.TopCountries)
	j4, _ := json.Marshal(stats.TopPaths)
	data := DashboardPageData{
		PageID:              "dashboard",
		UploadEnabled:       h.UploadEnabled,
		DashboardStats:      stats,
		RequestsByHourJSON:   string(j1),
		StatusDistJSON:      string(j2),
		TopCountriesJSON:    string(j3),
		TopPathsJSON:        string(j4),
	}
	if err := h.Template.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

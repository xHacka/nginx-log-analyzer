package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"github.com/xHacka/nginx-log-analyzer/internal/repository"
)

type DashboardHandler struct {
	Repo     repository.LogRepository
	Template *template.Template
}

type DashboardPageData struct {
	PageID string
	*repository.DashboardStats
	RequestsByHourJSON   template.JS
	StatusDistJSON       template.JS
	TopCountriesJSON     template.JS
	TopPathsJSON         template.JS
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
		DashboardStats:      stats,
		RequestsByHourJSON:   template.JS(j1),
		StatusDistJSON:      template.JS(j2),
		TopCountriesJSON:    template.JS(j3),
		TopPathsJSON:        template.JS(j4),
	}
	if err := h.Template.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

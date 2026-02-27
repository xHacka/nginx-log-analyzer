package handlers

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xHacka/nginx-log-analyzer/internal/models"
	"github.com/xHacka/nginx-log-analyzer/internal/repository"
)

const pageSize = 50

type QueryHandler struct {
	Repo          repository.LogRepository
	Template      *template.Template
	UploadEnabled bool
}

type SortableColumn struct {
	Name    string
	Field   string
	URL     string
	Active  bool
	Desc    bool
}

type QueryPageData struct {
	PageID        string
	UploadEnabled bool
	Entries       []models.LogEntry
	Total         int
	Page          int
	Pages         int
	Filters       QueryFormFilters
	PrevURL       string
	NextURL       string
	Columns       []SortableColumn
}

type QueryFormFilters struct {
	TimeFrom   string
	TimeTo     string
	Status     string
	Country    string
	PathContains string
	Method     string
	Host       string
	UserAgent  string
	SortBy     string
	SortDesc   bool
}

func (h *QueryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	filters := parseQueryFilters(r)
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}

	repoFilters := toRepoFilters(filters)
	offset := (page - 1) * pageSize
	entries, total, err := h.Repo.Query(repoFilters, pageSize, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pages := (total + pageSize - 1) / pageSize
	if pages < 1 {
		pages = 1
	}

	baseQuery := r.URL.Query()
	prevURL := ""
	if page > 1 {
		q := make(url.Values)
		for k, v := range baseQuery {
			if k != "page" {
				q[k] = v
			}
		}
		q.Set("page", strconv.Itoa(page-1))
		prevURL = "?" + q.Encode()
	}
	nextURL := ""
	if page < pages {
		q := make(url.Values)
		for k, v := range baseQuery {
			if k != "page" {
				q[k] = v
			}
		}
		q.Set("page", strconv.Itoa(page+1))
		nextURL = "?" + q.Encode()
	}

	columns := buildSortColumns(baseQuery, filters.SortBy, filters.SortDesc)

	data := QueryPageData{
		PageID:        "query",
		UploadEnabled: h.UploadEnabled,
		Entries:       entries,
		Total:   total,
		Page:    page,
		Pages:   pages,
		Filters: filters,
		PrevURL: prevURL,
		NextURL: nextURL,
		Columns: columns,
	}
	if err := h.Template.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func parseQueryFilters(r *http.Request) QueryFormFilters {
	return QueryFormFilters{
		TimeFrom:   r.URL.Query().Get("time_from"),
		TimeTo:     r.URL.Query().Get("time_to"),
		Status:     r.URL.Query().Get("status"),
		Country:    r.URL.Query().Get("country"),
		PathContains: r.URL.Query().Get("path"),
		Method:     r.URL.Query().Get("method"),
		Host:       r.URL.Query().Get("host"),
		UserAgent:  r.URL.Query().Get("user_agent"),
		SortBy:     r.URL.Query().Get("sort"),
		SortDesc:   r.URL.Query().Get("order") == "desc",
	}
}

func buildSortColumns(base url.Values, currentSort string, currentDesc bool) []SortableColumn {
	defs := []struct{ Name, Field string }{
		{"Time", "time"},
		{"IP", "remote_addr"},
		{"Host", "host"},
		{"Method", "method"},
		{"Path", "path"},
		{"Query", "query"},
		{"Protocol", "protocol"},
		{"Status", "status"},
		{"Bytes", "bytes"},
		{"City", "city"},
		{"Country", "country"},
		{"User Agent", "user_agent"},
	}
	if currentSort == "" {
		currentSort = "time"
	}
	cols := make([]SortableColumn, len(defs))
	for i, d := range defs {
		active := d.Field == currentSort
		newDesc := true
		if active && currentDesc {
			newDesc = false
		}
		q := make(url.Values)
		for k, v := range base {
			if k != "sort" && k != "order" && k != "page" {
				q[k] = v
			}
		}
		q.Set("sort", d.Field)
		if newDesc {
			q.Set("order", "desc")
		} else {
			q.Set("order", "asc")
		}
		cols[i] = SortableColumn{
			Name:   d.Name,
			Field:  d.Field,
			URL:    "?" + q.Encode(),
			Active: active,
			Desc:   currentDesc && active,
		}
	}
	return cols
}

func toRepoFilters(f QueryFormFilters) repository.QueryFilters {
	rf := repository.QueryFilters{SortBy: f.SortBy, SortDesc: f.SortDesc}
	if f.TimeFrom != "" {
		if t, err := time.Parse("2006-01-02T15:04", f.TimeFrom); err == nil {
			rf.TimeFrom = &t
		} else if t, err := time.Parse("2006-01-02", f.TimeFrom); err == nil {
			rf.TimeFrom = &t
		}
	}
	if f.TimeTo != "" {
		if t, err := time.Parse("2006-01-02T15:04", f.TimeTo); err == nil {
			rf.TimeTo = &t
		} else if t, err := time.Parse("2006-01-02", f.TimeTo); err == nil {
			rf.TimeTo = &t
		}
	}
	rf.Status = strings.TrimSpace(f.Status)
	rf.Country = f.Country
	rf.PathContains = f.PathContains
	rf.Method = f.Method
	rf.Host = f.Host
	rf.UserAgentContains = f.UserAgent
	return rf
}

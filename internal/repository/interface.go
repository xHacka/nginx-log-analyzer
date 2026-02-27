package repository

import (
	"time"

	"github.com/xHacka/nginx-log-analyzer/internal/models"
)

type QueryFilters struct {
	TimeFrom   *time.Time
	TimeTo     *time.Time
	Status     *int
	Country    string
	PathContains string
	Method     string
	Host       string
	UserAgentContains string
	SortBy     string // time, status, path, host, etc.
	SortDesc   bool
}

type DashboardStats struct {
	TotalRequests24h int64
	TotalRequests7d  int64
	ErrorRate24h     float64 // 4xx+5xx percentage
	UniqueIPs24h     int64
	RequestsByHour   []HourCount
	StatusDistribution []StatusCount
	TopCountries     []CountryCount
	TopPaths         []PathCount
}

type HourCount struct {
	Hour   string
	Count  int64
}

type StatusCount struct {
	Status int
	Count  int64
}

type CountryCount struct {
	Country string
	Count  int64
}

type PathCount struct {
	Path  string
	Count int64
}

type LogRepository interface {
	InsertBatch(entries []models.LogEntry) error
	Query(filters QueryFilters, limit, offset int) ([]models.LogEntry, int, error)
	GetDashboardStats(since time.Time) (*DashboardStats, error)
	DeleteOlderThan(t time.Time) error
}

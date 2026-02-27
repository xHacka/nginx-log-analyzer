package models

import "time"

// LogEntry matches nginx json_logs format.
// Note: nginx uses "q" for query args; we map to Query.
type LogEntry struct {
	ID         int64     `json:"id"`
	Time       float64   `json:"time"`        // epoch from $msec
	RemoteAddr string    `json:"remote_addr"`
	Host       string    `json:"host"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Query      string    `json:"query"`       // $args, stored as "q" in nginx
	Protocol   string    `json:"protocol"`
	Status     int       `json:"status"`
	Bytes      int64     `json:"bytes"`
	City       string    `json:"city"`
	Country    string    `json:"country"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
}

// NginxLogRow is the raw JSON structure from nginx (uses "q" for args).
type NginxLogRow struct {
	Time       string `json:"time"`
	RemoteAddr string `json:"remote_addr"`
	Host       string `json:"host"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Query      string `json:"q"`
	Protocol   string `json:"protocol"`
	Status     string `json:"status"`
	Bytes      string `json:"bytes"`
	City       string `json:"city"`
	Country    string `json:"country"`
	UserAgent  string `json:"user_agent"`
}

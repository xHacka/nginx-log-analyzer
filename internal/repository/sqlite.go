package repository

import (
	"database/sql"
	"strings"
	"time"

	"github.com/xHacka/nginx-log-analyzer/internal/models"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS log_entries (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	time REAL NOT NULL,
	remote_addr TEXT,
	host TEXT,
	method TEXT,
	path TEXT,
	query TEXT,
	protocol TEXT,
	status INTEGER,
	bytes INTEGER,
	city TEXT,
	country TEXT,
	user_agent TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_log_entries_time ON log_entries(time);
CREATE INDEX IF NOT EXISTS idx_log_entries_status ON log_entries(status);
CREATE INDEX IF NOT EXISTS idx_log_entries_country ON log_entries(country);
CREATE INDEX IF NOT EXISTS idx_log_entries_path ON log_entries(path);
CREATE INDEX IF NOT EXISTS idx_log_entries_host ON log_entries(host);
CREATE INDEX IF NOT EXISTS idx_log_entries_created_at ON log_entries(created_at);
`

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLite(dbPath string) (*SQLiteRepository, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteRepository{db: db}, nil
}

func (r *SQLiteRepository) InsertBatch(entries []models.LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO log_entries (time, remote_addr, host, method, path, query, protocol, status, bytes, city, country, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		_, err := stmt.Exec(e.Time, e.RemoteAddr, e.Host, e.Method, e.Path, e.Query, e.Protocol, e.Status, e.Bytes, e.City, e.Country, e.UserAgent)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *SQLiteRepository) Query(filters QueryFilters, limit, offset int) ([]models.LogEntry, int, error) {
	var args []interface{}
	var where []string

	if filters.TimeFrom != nil {
		where = append(where, "time >= ?")
		args = append(args, float64(filters.TimeFrom.UnixNano())/1e9)
	}
	if filters.TimeTo != nil {
		where = append(where, "time <= ?")
		args = append(args, float64(filters.TimeTo.UnixNano())/1e9)
	}
	if filters.Status != nil {
		where = append(where, "status = ?")
		args = append(args, *filters.Status)
	}
	if filters.Country != "" {
		where = append(where, "country = ?")
		args = append(args, filters.Country)
	}
	if filters.PathContains != "" {
		where = append(where, "path LIKE ?")
		args = append(args, "%"+filters.PathContains+"%")
	}
	if filters.Method != "" {
		where = append(where, "method = ?")
		args = append(args, filters.Method)
	}
	if filters.Host != "" {
		where = append(where, "host = ?")
		args = append(args, filters.Host)
	}
	if filters.UserAgentContains != "" {
		where = append(where, "user_agent LIKE ?")
		args = append(args, "%"+filters.UserAgentContains+"%")
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}

	orderBy := "time"
	if filters.SortBy != "" {
		allowed := map[string]bool{"time": true, "status": true, "path": true, "host": true, "remote_addr": true, "bytes": true}
		if allowed[filters.SortBy] {
			orderBy = filters.SortBy
		}
	}
	dir := "ASC"
	if filters.SortDesc {
		dir = "DESC"
	}

	// Count total
	var total int
	countSQL := "SELECT COUNT(*) FROM log_entries" + whereClause
	if err := r.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Query rows
	args = append(args, limit, offset)
	rows, err := r.db.Query(
		"SELECT id, time, remote_addr, host, method, path, query, protocol, status, bytes, city, country, user_agent, created_at FROM log_entries"+whereClause+
			" ORDER BY "+orderBy+" "+dir+" LIMIT ? OFFSET ?",
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []models.LogEntry
	for rows.Next() {
		var e models.LogEntry
		var createdAt sql.NullTime
		err := rows.Scan(&e.ID, &e.Time, &e.RemoteAddr, &e.Host, &e.Method, &e.Path, &e.Query, &e.Protocol, &e.Status, &e.Bytes, &e.City, &e.Country, &e.UserAgent, &createdAt)
		if err != nil {
			return nil, 0, err
		}
		if createdAt.Valid {
			e.CreatedAt = createdAt.Time
		}
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

func (r *SQLiteRepository) GetDashboardStats(since time.Time) (*DashboardStats, error) {
	sinceEpoch := float64(since.UnixNano()) / 1e9
	stats := &DashboardStats{}

	// Total requests 24h
	r.db.QueryRow("SELECT COUNT(*) FROM log_entries WHERE time >= ?", sinceEpoch).Scan(&stats.TotalRequests24h)

	// Total requests 7d
	sevenDaysAgo := since.Add(-6 * 24 * time.Hour)
	sevenDaysEpoch := float64(sevenDaysAgo.UnixNano()) / 1e9
	r.db.QueryRow("SELECT COUNT(*) FROM log_entries WHERE time >= ?", sevenDaysEpoch).Scan(&stats.TotalRequests7d)

	// Error rate 24h (4xx + 5xx)
	var errors int64
	r.db.QueryRow("SELECT COUNT(*) FROM log_entries WHERE time >= ? AND status >= 400", sinceEpoch).Scan(&errors)
	if stats.TotalRequests24h > 0 {
		stats.ErrorRate24h = float64(errors) / float64(stats.TotalRequests24h) * 100
	}

	// Unique IPs 24h
	r.db.QueryRow("SELECT COUNT(DISTINCT remote_addr) FROM log_entries WHERE time >= ?", sinceEpoch).Scan(&stats.UniqueIPs24h)

	// Requests by hour (last 24h)
	rows, err := r.db.Query(`
		SELECT strftime('%Y-%m-%d %H:00', datetime(time, 'unixepoch', 'localtime')) as hour, COUNT(*) as cnt
		FROM log_entries WHERE time >= ?
		GROUP BY hour ORDER BY hour
	`, sevenDaysEpoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var hc HourCount
		rows.Scan(&hc.Hour, &hc.Count)
		stats.RequestsByHour = append(stats.RequestsByHour, hc)
	}

	// Status distribution
	rows2, err := r.db.Query("SELECT status, COUNT(*) FROM log_entries WHERE time >= ? GROUP BY status ORDER BY status", sinceEpoch)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var sc StatusCount
		rows2.Scan(&sc.Status, &sc.Count)
		stats.StatusDistribution = append(stats.StatusDistribution, sc)
	}

	// Top countries
	rows3, err := r.db.Query(`
		SELECT COALESCE(country, '') as c, COUNT(*) FROM log_entries WHERE time >= ? GROUP BY c ORDER BY COUNT(*) DESC LIMIT 10
	`, sinceEpoch)
	if err != nil {
		return nil, err
	}
	defer rows3.Close()
	for rows3.Next() {
		var cc CountryCount
		rows3.Scan(&cc.Country, &cc.Count)
		stats.TopCountries = append(stats.TopCountries, cc)
	}

	// Top paths
	rows4, err := r.db.Query(`
		SELECT path, COUNT(*) FROM log_entries WHERE time >= ? GROUP BY path ORDER BY COUNT(*) DESC LIMIT 10
	`, sinceEpoch)
	if err != nil {
		return nil, err
	}
	defer rows4.Close()
	for rows4.Next() {
		var pc PathCount
		rows4.Scan(&pc.Path, &pc.Count)
		stats.TopPaths = append(stats.TopPaths, pc)
	}

	return stats, nil
}

func (r *SQLiteRepository) DeleteOlderThan(t time.Time) error {
	epoch := float64(t.UnixNano()) / 1e9
	_, err := r.db.Exec("DELETE FROM log_entries WHERE time < ?", epoch)
	return err
}

func (r *SQLiteRepository) Close() error {
	return r.db.Close()
}

package ingest

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/xHacka/nginx-log-analyzer/internal/models"
	"github.com/xHacka/nginx-log-analyzer/internal/repository"
)

const batchSize = 1000

// ParseJSONLines reads newline-delimited JSON and returns LogEntry slice.
func ParseJSONLines(r io.Reader) ([]models.LogEntry, error) {
	var entries []models.LogEntry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var row models.NginxLogRow
		if err := json.Unmarshal(line, &row); err != nil {
			continue // skip malformed lines
		}
		e := parseRow(&row)
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

func parseRow(row *models.NginxLogRow) models.LogEntry {
	var e models.LogEntry
	e.RemoteAddr = row.RemoteAddr
	e.Host = row.Host
	e.Method = row.Method
	e.Path = row.Path
	e.Query = row.Query
	e.Protocol = row.Protocol
	e.City = row.City
	e.Country = row.Country
	e.UserAgent = row.UserAgent

	if t, err := strconv.ParseFloat(row.Time, 64); err == nil {
		e.Time = t
	}
	if s, err := strconv.Atoi(row.Status); err == nil {
		e.Status = s
	}
	if b, err := strconv.ParseInt(row.Bytes, 10, 64); err == nil {
		e.Bytes = b
	}
	e.CreatedAt = time.Now()
	return e
}

// IngestFile reads a file and inserts entries into the repository.
func IngestFile(path string, repo repository.LogRepository) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	entries, err := ParseJSONLines(f)
	if err != nil {
		return 0, err
	}
	if err := repo.InsertBatch(entries); err != nil {
		return 0, err
	}
	return len(entries), nil
}

// IngestReader reads from an io.Reader (e.g. uploaded file) and inserts.
func IngestReader(r io.Reader, repo repository.LogRepository) (int, error) {
	entries, err := ParseJSONLines(r)
	if err != nil {
		return 0, err
	}
	// Batch insert
	for i := 0; i < len(entries); i += batchSize {
		end := i + batchSize
		if end > len(entries) {
			end = len(entries)
		}
		if err := repo.InsertBatch(entries[i:end]); err != nil {
			return i, err
		}
	}
	return len(entries), nil
}

// TailFile watches a file for changes and ingests new lines.
func TailFile(path string, repo repository.LogRepository, stopCh <-chan struct{}) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	if err := watcher.Add(path); err != nil {
		return err
	}

	// Get current file size to start reading from
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	offset := info.Size()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				ingestNewLines(path, &offset, repo)
			}
		case err := <-watcher.Errors:
			if err != nil {
				log.Printf("fsnotify error: %v", err)
			}
		case <-ticker.C:
			ingestNewLines(path, &offset, repo)
		}
	}
}

func ingestNewLines(path string, offset *int64, repo repository.LogRepository) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(*offset, 0); err != nil {
		return
	}
	entries, err := ParseJSONLines(f)
	if err != nil {
		return
	}
	if len(entries) > 0 {
		if err := repo.InsertBatch(entries); err != nil {
			log.Printf("ingest error: %v", err)
		} else {
			if info, err := f.Stat(); err == nil {
				*offset = info.Size()
			}
		}
	}
}

// ReadFullFileAndTail reads existing content first, then tails.
func ReadFullFileAndTail(path string, repo repository.LogRepository, stopCh <-chan struct{}) error {
	n, err := IngestFile(path, repo)
	if err != nil {
		return err
	}
	if n > 0 {
		log.Printf("Ingested %d lines from %s", n, path)
	}
	return TailFile(path, repo, stopCh)
}

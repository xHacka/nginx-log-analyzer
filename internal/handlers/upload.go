package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/xHacka/nginx-log-analyzer/internal/ingest"
	"github.com/xHacka/nginx-log-analyzer/internal/repository"
)

type UploadHandler struct {
	Repo  repository.LogRepository
	Rules ingest.FilterRules
}

func (h *UploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file, _, err := r.FormFile("logfile")
	if err != nil {
		http.Error(w, "No file uploaded or invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	n, err := ingest.IngestReader(file, h.Repo, h.Rules)
	if err != nil {
		http.Error(w, "Failed to ingest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"ingested": n})
}

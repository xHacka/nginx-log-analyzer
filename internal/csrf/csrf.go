package csrf

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

const (
	cookieName = "csrf_token"
	headerName = "X-CSRF-Token"
	tokenLen   = 32
)

func generateToken() (string, error) {
	b := make([]byte, tokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Protect implements the double-submit cookie pattern.
// GET/HEAD/OPTIONS: ensures a csrf_token cookie is set (readable by JS).
// POST/PUT/DELETE: requires X-CSRF-Token header to match the cookie value.
func Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			if _, err := r.Cookie(cookieName); err != nil {
				token, err := generateToken()
				if err != nil {
					http.Error(w, "Internal error", http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Name:     cookieName,
					Value:    token,
					Path:     "/",
					HttpOnly: false,
					SameSite: http.SameSiteStrictMode,
				})
			}
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(cookieName)
		if err != nil || cookie.Value == "" {
			http.Error(w, "Forbidden: missing CSRF token", http.StatusForbidden)
			return
		}
		if headerToken := r.Header.Get(headerName); headerToken == "" || headerToken != cookie.Value {
			http.Error(w, "Forbidden: invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

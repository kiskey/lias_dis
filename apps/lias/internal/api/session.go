package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	browserSessionCookie = "lias_session"
	browserCSRFCookie    = "lias_csrf"
	browserCSRFHeader    = "X-CSRF-Token"
	browserSessionTTL    = 8 * time.Hour
)

type browserSession struct {
	csrf      string
	expiresAt time.Time
}

type browserSessionManager struct {
	mu         sync.Mutex
	sessions   map[[32]byte]browserSession
	authDigest [32]byte
	authSet    bool
	secure     bool
	now        func() time.Time
}

func newBrowserSessionManager() *browserSessionManager {
	return &browserSessionManager{sessions: make(map[[32]byte]browserSession), now: time.Now}
}

func (m *browserSessionManager) configure(authToken string, secure bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authDigest = sha256.Sum256([]byte(authToken))
	m.authSet = authToken != ""
	m.secure = secure
}

func randomBrowserToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (m *browserSessionManager) create(providedToken string) (string, string, time.Time, bool) {
	providedDigest := sha256.Sum256([]byte(providedToken))
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.authSet || subtle.ConstantTimeCompare(providedDigest[:], m.authDigest[:]) != 1 {
		return "", "", time.Time{}, false
	}
	sessionID, err := randomBrowserToken()
	if err != nil {
		return "", "", time.Time{}, false
	}
	csrf, err := randomBrowserToken()
	if err != nil {
		return "", "", time.Time{}, false
	}
	expires := m.now().Add(browserSessionTTL)
	m.sessions[sha256.Sum256([]byte(sessionID))] = browserSession{csrf: csrf, expiresAt: expires}
	return sessionID, csrf, expires, true
}

func (m *browserSessionManager) lookup(r *http.Request) (browserSession, [32]byte, bool) {
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil || cookie.Value == "" {
		return browserSession{}, [32]byte{}, false
	}
	digest := sha256.Sum256([]byte(cookie.Value))
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[digest]
	if !ok {
		return browserSession{}, digest, false
	}
	if !session.expiresAt.After(m.now()) {
		delete(m.sessions, digest)
		return browserSession{}, digest, false
	}
	return session, digest, true
}

func (m *browserSessionManager) authenticate(r *http.Request) bool {
	_, _, ok := m.lookup(r)
	return ok
}

func (m *browserSessionManager) validateCSRF(r *http.Request) bool {
	session, _, ok := m.lookup(r)
	if !ok {
		return false
	}
	cookie, err := r.Cookie(browserCSRFCookie)
	if err != nil || cookie.Value == "" || r.Header.Get(browserCSRFHeader) == "" {
		return false
	}
	cookieDigest := sha256.Sum256([]byte(cookie.Value))
	headerDigest := sha256.Sum256([]byte(r.Header.Get(browserCSRFHeader)))
	expectedDigest := sha256.Sum256([]byte(session.csrf))
	return subtle.ConstantTimeCompare(cookieDigest[:], expectedDigest[:]) == 1 &&
		subtle.ConstantTimeCompare(headerDigest[:], expectedDigest[:]) == 1
}

func (m *browserSessionManager) delete(r *http.Request) {
	_, digest, ok := m.lookup(r)
	if !ok {
		return
	}
	m.mu.Lock()
	delete(m.sessions, digest)
	m.mu.Unlock()
}

func (h *Handlers) CreateBrowserSession(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Token == "" {
		http.Error(w, `{"error":"a valid token is required"}`, http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, `{"error":"request body must contain one JSON value"}`, http.StatusBadRequest)
		return
	}
	sessionID, csrf, expires, ok := h.sessions.create(request.Token)
	if !ok {
		http.Error(w, `{"error":"invalid authentication token"}`, http.StatusUnauthorized)
		return
	}
	maxAge := int(time.Until(expires).Seconds())
	h.setBrowserCookie(w, browserSessionCookie, sessionID, true, maxAge, expires)
	h.setBrowserCookie(w, browserCSRFCookie, csrf, false, maxAge, expires)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) DeleteBrowserSession(w http.ResponseWriter, r *http.Request) {
	if !h.sessions.authenticate(r) {
		http.Error(w, `{"error":"invalid or expired session"}`, http.StatusUnauthorized)
		return
	}
	if !h.sessions.validateCSRF(r) {
		http.Error(w, `{"error":"invalid or missing CSRF token"}`, http.StatusForbidden)
		return
	}
	h.sessions.delete(r)
	h.setBrowserCookie(w, browserSessionCookie, "", true, -1, time.Unix(1, 0))
	h.setBrowserCookie(w, browserCSRFCookie, "", false, -1, time.Unix(1, 0))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) setBrowserCookie(w http.ResponseWriter, name, value string, httpOnly bool, maxAge int, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: httpOnly,
		Secure: h.secureCookies, SameSite: http.SameSiteStrictMode,
		MaxAge: maxAge, Expires: expires,
	})
}

func isMutatingMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

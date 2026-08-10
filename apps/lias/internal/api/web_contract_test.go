package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readWebAsset(t *testing.T, name ...string) string {
	t.Helper()
	parts := append([]string{"..", "..", "web"}, name...)
	data, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDashboardStoredXSSAndSessionContract(t *testing.T) {
	mainJS := readWebAsset(t, "src", "main.js")
	apiJS := readWebAsset(t, "src", "api.js")
	index := readWebAsset(t, "index.html")
	styles := readWebAsset(t, "src", "styles.css")

	for _, required := range []string{
		"export function escapeHTML", "name.startsWith('on')", "javascript:|@import",
		"toast.textContent = String(msg)", "setSafeHTML(document.getElementById('modal-body')",
	} {
		if !strings.Contains(mainJS, required) {
			t.Fatalf("dashboard XSS control missing %q", required)
		}
	}
	if strings.Contains(mainJS, "toast.innerHTML") || strings.Contains(mainJS, "insertAdjacentHTML") {
		t.Fatal("dashboard contains a direct unsafe rendering sink")
	}
	for _, hostile := range []string{`<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<a href="javascript:alert(1)">`} {
		escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(hostile)
		if strings.Contains(escaped, "<img") || strings.Contains(escaped, "<svg") || strings.Contains(escaped, "<a ") {
			t.Fatalf("hostile fixture remained markup: %s", escaped)
		}
	}
	for _, required := range []string{"credentials: 'same-origin'", "X-CSRF-Token", "new EventSource('/api/v1/events', { withCredentials: true })"} {
		if !strings.Contains(apiJS, required) {
			t.Fatalf("browser session client contract missing %q", required)
		}
	}
	if !strings.Contains(index, `script-src 'self'`) || !strings.Contains(index, `aria-labelledby="modal-title"`) {
		t.Fatal("dashboard CSP or dialog labelling is missing")
	}
	if !strings.Contains(styles, ".modal-backdrop.hidden { opacity: 0; visibility: hidden;") {
		t.Fatal("closed modal must be removed from keyboard and accessibility navigation")
	}
}

func TestIdentityReviewRequiresExplicitDestructiveConfirmation(t *testing.T) {
	mainJS := readWebAsset(t, "src", "main.js")
	index := readWebAsset(t, "index.html")
	for _, required := range []string{
		"Type <strong>MERGE</strong> to confirm", "phrase.value !== 'MERGE'", "identity-merge-submit\" disabled",
		"Type <strong>SPLIT</strong> to confirm", "phrase.value !== 'SPLIT'", "identity-split-submit\" disabled",
		"Correlation score ${score}% — not proof", "expected_updated_at", "identity-reject-note",
	} {
		if !strings.Contains(mainJS, required) {
			t.Fatalf("identity decision safeguard missing %q", required)
		}
	}
	if !strings.Contains(index, `data-view="identity"`) || !strings.Contains(index, `aria-label="pending identity matches"`) {
		t.Fatal("identity review navigation or accessible badge is missing")
	}
}

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/rs/zerolog"

	"github.com/cli-auth/cli-box/internal/adminui"
	"github.com/cli-auth/cli-box/pkg/admin"
)

func newAdminServerForTest(t *testing.T) *AdminServer {
	t.Helper()

	runtime := &ServerRuntime{
		logger: zerolog.Nop(),
		events: admin.NewEventStore(16),
		auth:   admin.NewAuthStore(t.TempDir() + "/admin-auth.json"),
		ui: adminui.NewWithFS(fstest.MapFS{
			"index.html":    &fstest.MapFile{Data: []byte("<html>admin ui</html>")},
			"assets/app.js": &fstest.MapFile{Data: []byte("console.log('ok')")},
		}),
	}

	server, err := NewAdminServer(runtime)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestAdminUIServesEmbeddedIndexForSPARoute(t *testing.T) {
	server := newAdminServerForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/policies", nil)
	rec := httptest.NewRecorder()
	server.echo.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != "<html>admin ui</html>" {
		t.Fatalf("unexpected body %q", got)
	}
}

func TestAdminUIServesEmbeddedAsset(t *testing.T) {
	server := newAdminServerForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	rec := httptest.NewRecorder()
	server.echo.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != "console.log('ok')" {
		t.Fatalf("unexpected asset body %q", got)
	}
}

func TestAdminAPIRemainsJSON(t *testing.T) {
	server := newAdminServerForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/session/me", nil)
	rec := httptest.NewRecorder()
	server.echo.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response: %v", err)
	}
}

func TestUnknownAPIRouteDoesNotFallBackToSPA(t *testing.T) {
	server := newAdminServerForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/unknown", nil)
	rec := httptest.NewRecorder()
	server.echo.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if got := rec.Body.String(); strings.Contains(got, "admin ui") {
		t.Fatalf("unexpected SPA fallback body %q", got)
	}
}

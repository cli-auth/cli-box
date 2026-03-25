package adminui

import (
	"testing"
	"testing/fstest"
)

func TestNewWithFSEnabledWhenIndexExists(t *testing.T) {
	app := NewWithFS(fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<html>ok</html>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('ok')")},
	})

	if !app.Enabled() {
		t.Fatal("expected embedded UI to be enabled when index.html exists")
	}
	if _, err := app.Stat("assets/app.js"); err != nil {
		t.Fatalf("expected assets/app.js to exist: %v", err)
	}
}

func TestNewWithFSDisabledWithoutIndex(t *testing.T) {
	app := NewWithFS(fstest.MapFS{
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('ok')")},
	})

	if app.Enabled() {
		t.Fatal("expected embedded UI to be disabled when index.html is absent")
	}
}

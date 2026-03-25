package adminui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embeddedFiles embed.FS

type App struct {
	files fs.FS
	index []byte
}

func Load() *App {
	sub, err := fs.Sub(embeddedFiles, "dist")
	if err != nil {
		return &App{}
	}
	return NewWithFS(sub)
}

func NewWithFS(files fs.FS) *App {
	index, _ := fs.ReadFile(files, "index.html")
	return &App{
		files: files,
		index: index,
	}
}

func (a *App) Enabled() bool {
	if a == nil {
		return false
	}
	return len(a.index) > 0
}

func (a *App) Files() fs.FS {
	if a == nil {
		return nil
	}
	return a.files
}

func (a *App) Index() []byte {
	if a == nil {
		return nil
	}
	return a.index
}

func (a *App) Stat(path string) (fs.FileInfo, error) {
	if a == nil || a.files == nil {
		return nil, fs.ErrNotExist
	}
	return fs.Stat(a.files, path)
}

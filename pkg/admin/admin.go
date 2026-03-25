package admin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/samber/oops"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"github.com/cli-auth/cli-box/pkg/policy"
)

type EventStore struct {
	mu sync.Mutex
	db *sql.DB
}

type RuntimeEvent struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	Timestamp time.Time         `json:"timestamp"`
	Data      map[string]string `json:"data,omitempty"`
}

const eventsDDL = `
CREATE TABLE IF NOT EXISTS events (
	id        TEXT     PRIMARY KEY,
	type      TEXT     NOT NULL,
	level     TEXT     NOT NULL,
	message   TEXT     NOT NULL,
	timestamp DATETIME NOT NULL,
	data      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
`

func NewEventStore(path string) (*EventStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, oops.In("events").Wrapf(err, "create events dir")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, oops.In("events").Wrapf(err, "open events db")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, oops.In("events").Wrapf(err, "set events db permissions")
	}
	if _, err := db.Exec(eventsDDL); err != nil {
		db.Close()
		return nil, oops.In("events").Wrapf(err, "init events schema")
	}
	return &EventStore{db: db}, nil
}

func (s *EventStore) Add(eventType, level, message string, data map[string]string) {
	if s == nil {
		return
	}

	var dataJSON []byte
	if len(data) > 0 {
		dataJSON, _ = json.Marshal(data)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO events (id, type, level, message, timestamp, data) VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.Must(uuid.NewV7()).String(), eventType, level, message, time.Now().UTC().Format(time.RFC3339Nano), string(dataJSON),
	)
	if err != nil {
		log.Error().Err(err).Msg("audit log write failed")
	}
}

type EventQuery struct {
	MinLevel string // "verbose"|"info"|"warn"|"error"; default "info"
	Q        string // substring search on message and type
	Limit    int    // page size; default 25
	Offset   int    // pagination offset
}

type EventPage struct {
	Events []RuntimeEvent
	Total  int
}

var levelOrder = map[string]int{
	"verbose": 0,
	"info":    1,
	"warn":    2,
	"error":   3,
}

func (s *EventStore) Search(q EventQuery) EventPage {
	minLvl, ok := levelOrder[q.MinLevel]
	if !ok {
		minLvl = 1 // default: info
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	search := ""
	if q.Q != "" {
		search = "%" + q.Q + "%"
	}

	const whereClause = `
		CASE level WHEN 'verbose' THEN 0 WHEN 'info' THEN 1 WHEN 'warn' THEN 2 WHEN 'error' THEN 3 ELSE 1 END >= ?
		AND (? = '' OR message LIKE ? OR type LIKE ? OR data LIKE ?)`

	s.mu.Lock()
	defer s.mu.Unlock()

	var total int
	_ = s.db.QueryRow(
		`SELECT COUNT(*) FROM events WHERE`+whereClause,
		minLvl, search, search, search, search,
	).Scan(&total)

	rows, err := s.db.Query(
		`SELECT id, type, level, message, timestamp, data FROM events WHERE`+whereClause+
			` ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
		minLvl, search, search, search, search, limit, q.Offset,
	)
	if err != nil {
		log.Error().Err(err).Msg("audit log read failed")
		return EventPage{Total: total}
	}
	defer rows.Close()

	var events []RuntimeEvent
	for rows.Next() {
		var e RuntimeEvent
		var ts string
		var dataStr sql.NullString
		if err := rows.Scan(&e.ID, &e.Type, &e.Level, &e.Message, &ts, &dataStr); err != nil {
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		if dataStr.Valid && dataStr.String != "" {
			_ = json.Unmarshal([]byte(dataStr.String), &e.Data)
		}
		events = append(events, e)
	}
	return EventPage{Events: events, Total: total}
}

func (s *EventStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

type AuthStore struct {
	path     string
	mu       sync.Mutex
	sessions map[string]time.Time
}

type authState struct {
	PasswordHash string    `json:"passwordHash"`
	CreatedAt    time.Time `json:"createdAt"`
}

func NewAuthStore(path string) *AuthStore {
	return &AuthStore{
		path:     path,
		sessions: make(map[string]time.Time),
	}
}

func (s *AuthStore) IsConfigured() bool {
	_, err := s.loadState()
	return err == nil
}

func (s *AuthStore) Bootstrap(password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.loadState(); err == nil {
		return oops.In("admin").Errorf("admin password already configured")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return oops.In("admin").Wrapf(err, "hash password")
	}

	state := authState{
		PasswordHash: string(hash),
		CreatedAt:    time.Now().UTC(),
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return oops.In("admin").Wrapf(err, "create admin state dir")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return oops.In("admin").Wrapf(err, "marshal admin state")
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return oops.In("admin").Wrapf(err, "write admin state")
	}
	return nil
}

func (s *AuthStore) Login(password string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.loadState()
	if err != nil {
		return "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(state.PasswordHash), []byte(password)); err != nil {
		return "", oops.In("admin").Errorf("invalid credentials")
	}

	token := strconv.FormatInt(time.Now().UnixNano(), 36)
	s.sessions[token] = time.Now().UTC()
	return token, nil
}

func (s *AuthStore) Authenticated(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[token]
	return ok
}

func (s *AuthStore) Logout(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *AuthStore) loadState() (authState, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return authState{}, err
	}
	var state authState
	if err := json.Unmarshal(data, &state); err != nil {
		return authState{}, oops.In("admin").Wrapf(err, "read admin state")
	}
	if state.PasswordHash == "" {
		return authState{}, oops.In("admin").Errorf("admin password hash missing")
	}
	return state, nil
}

type TransportStatus struct {
	Configured  bool   `json:"configured"`
	Initialized bool   `json:"initialized"`
	Listening   bool   `json:"listening"`
	Listen      string `json:"listen"`
	Address     string `json:"address,omitempty"`
}

type PairingStatus struct {
	Initialized       bool      `json:"initialized"`
	StateDir          string    `json:"stateDir"`
	ServerFingerprint string    `json:"serverFingerprint,omitempty"`
	TokenPresent      bool      `json:"tokenPresent"`
	Token             string    `json:"token,omitempty"`
	TokenExpiresAt    time.Time `json:"tokenExpiresAt,omitempty"`
	TokenError        string    `json:"tokenError,omitempty"`
}

type ServerConfigResponse struct {
	Listen        string `json:"listen"`
	StateDir      string `json:"stateDir"`
	FuseMountBase string `json:"fuseMountBase"`
	SecureDir     string `json:"secureDir"`
	PolicyDir     string `json:"policyDir"`
	MountPolicy   string `json:"mountPolicy"`
	Sandbox       bool   `json:"sandbox"`
}

type ServerStatusResponse struct {
	StartedAt       time.Time       `json:"startedAt"`
	UptimeSeconds   int64           `json:"uptimeSeconds"`
	Transport       TransportStatus `json:"transport"`
	Pairing         PairingStatus   `json:"pairing"`
	PolicyCount     int             `json:"policyCount"`
	BootstrapNeeded bool            `json:"bootstrapNeeded"`
}

type PolicySummary struct {
	Name      string    `json:"name"`
	Disabled  bool      `json:"disabled,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type PolicyDocument struct {
	Name      string    `json:"name"`
	Source    string    `json:"source"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func CloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func WritePolicyFileAtomically(path, source string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return oops.In("policy").Wrapf(err, "create policy dir")
	}
	tempPath := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tempPath, []byte(source), 0o600); err != nil {
		return oops.In("policy").Wrapf(err, "write temporary policy file")
	}
	if err := os.Rename(tempPath, path); err != nil {
		return oops.In("policy").Wrapf(err, "replace policy file")
	}
	return nil
}

func ValidatePolicySource(policyDir, name, source string) error {
	tempDir, err := os.MkdirTemp("", "cli-box-policy-validate-*")
	if err != nil {
		return oops.In("policy").Wrapf(err, "create temporary policy dir")
	}
	defer os.RemoveAll(tempDir)

	entries, err := policy.ListDir(policyDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry == name {
			continue
		}
		data, err := os.ReadFile(filepath.Join(policyDir, entry))
		if err != nil {
			return oops.In("policy").Wrapf(err, "read policy %q", entry)
		}
		if err := os.WriteFile(filepath.Join(tempDir, entry), data, 0o644); err != nil {
			return oops.In("policy").Wrapf(err, "copy policy %q", entry)
		}
	}
	if err := os.WriteFile(filepath.Join(tempDir, name), []byte(source), 0o644); err != nil {
		return oops.In("policy").Wrapf(err, "write validation policy")
	}
	return policy.ValidateDir(tempDir)
}

func ReadPolicyDocument(policyDir, name string) (PolicyDocument, error) {
	path := filepath.Join(policyDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return PolicyDocument{}, oops.In("policy").Wrapf(err, "read policy %q", name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return PolicyDocument{}, oops.In("policy").Wrapf(err, "stat policy %q", name)
	}
	return PolicyDocument{
		Name:      name,
		Source:    string(data),
		UpdatedAt: info.ModTime().UTC(),
	}, nil
}

func ListPolicyDocuments(policyDir string) ([]PolicySummary, error) {
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, oops.In("policy").Wrapf(err, "read policy dir")
	}
	var summaries []PolicySummary
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		disabled := false
		if strings.HasSuffix(name, ".star.disabled") {
			disabled = true
		} else if filepath.Ext(name) != ".star" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, oops.In("policy").Wrapf(err, "stat policy %q", name)
		}
		summaries = append(summaries, PolicySummary{
			Name:      name,
			Disabled:  disabled,
			UpdatedAt: info.ModTime().UTC(),
		})
	}
	slices.SortFunc(summaries, func(a, b PolicySummary) int {
		if a.Name == "_init.star" {
			return -1
		}
		if b.Name == "_init.star" {
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return summaries, nil
}

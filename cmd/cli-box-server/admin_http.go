package main

import (
	"context"
	_ "embed"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/cli-auth/cli-box/pkg/admin"
	"github.com/cli-auth/cli-box/pkg/pki"
)

//go:embed skill.md
var skillTemplate []byte

const adminSessionCookie = "cli_box_admin_session"

type AdminServer struct {
	runtime *ServerRuntime
	echo    *echo.Echo
	server  *http.Server
}

type sessionResponse struct {
	Authenticated   bool `json:"authenticated"`
	BootstrapNeeded bool `json:"bootstrapNeeded"`
}

type passwordRequest struct {
	Password string `json:"password"`
}

type pairingInitRequest struct {
	Hosts string `json:"hosts"`
}

type policyBody struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type validationResponse struct {
	OK     bool     `json:"ok"`
	Errors []string `json:"errors"`
}

func NewAdminServer(runtime *ServerRuntime) (*AdminServer, error) {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:      true,
		LogStatus:   true,
		LogMethod:   true,
		LogRemoteIP: true,
		HandleError: true,
		LogValuesFunc: func(c echo.Context, values middleware.RequestLoggerValues) error {
			runtime.logger.Info().
				Str("method", values.Method).
				Str("uri", values.URI).
				Int("status", values.Status).
				Str("remote", values.RemoteIP).
				Msg("admin request")
			return nil
		},
	}))
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		status := http.StatusInternalServerError
		message := "internal error"

		var httpErr *echo.HTTPError
		switch {
		case errors.As(err, &httpErr):
			status = httpErr.Code
			if text, ok := httpErr.Message.(string); ok {
				message = text
			}
		default:
			message = err.Error()
		}

		if !c.Response().Committed {
			_ = c.JSON(status, map[string]any{
				"error": message,
			})
		}
	}

	s := &AdminServer{
		runtime: runtime,
		echo:    e,
		server:  &http.Server{Handler: e},
	}

	s.registerRoutes()
	return s, nil
}

func (s *AdminServer) Serve(ln net.Listener) {
	s.runtime.logger.Info().Stringer("addr", ln.Addr()).Msg("admin listening")
	s.runtime.events.Add("admin.started", "info", "admin server started", map[string]string{
		"addr": ln.Addr().String(),
	})
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.runtime.logger.Error().Err(err).Msg("admin server failed")
		}
	}()
}

func (s *AdminServer) Close(ctx context.Context) error {
	return s.echo.Shutdown(ctx)
}

func (s *AdminServer) registerRoutes() {
	api := s.echo.Group("/api/admin")
	api.GET("/session/me", s.handleSession)
	api.POST("/bootstrap", s.handleBootstrap)
	api.POST("/session/login", s.handleLogin)
	api.POST("/session/logout", s.handleLogout, s.requireAuth)

	protected := api.Group("", s.requireAuth)
	protected.GET("/server/config", s.handleServerConfig)
	protected.GET("/server/status", s.handleServerStatus)
	protected.GET("/pairing/current", s.handlePairingCurrent)
	protected.POST("/pairing/init", s.handlePairingInit)
	protected.POST("/pairing/token", s.handlePairingToken)
	protected.GET("/policies", s.handlePolicies)
	protected.GET("/policies/:name", s.handlePolicy)
	protected.POST("/policies", s.handleCreatePolicy)
	protected.PUT("/policies/:name", s.handleSavePolicy)
	protected.DELETE("/policies/:name", s.handleDeletePolicy)
	protected.POST("/policies/:name/toggle", s.handleTogglePolicy)
	protected.POST("/policies/validate", s.handleValidatePolicy)
	protected.GET("/runtime/events", s.handleRuntimeEvents)

	s.echo.GET("/skill", s.handleSkill)
	s.registerUIRoutes()
}

func (s *AdminServer) registerUIRoutes() {
	if !s.runtime.ui.Enabled() {
		s.runtime.logger.Warn().Msg("admin UI assets not embedded; serving API only")
		return
	}

	fileServer := http.FileServer(http.FS(s.runtime.ui.Files()))
	handler := echo.WrapHandler(http.StripPrefix("/", fileServer))

	s.echo.GET("/*", func(c echo.Context) error {
		return s.serveUIRoute(c, handler)
	})
	s.echo.HEAD("/*", func(c echo.Context) error {
		return s.serveUIRoute(c, handler)
	})
}

func (s *AdminServer) serveUIRoute(c echo.Context, fileHandler echo.HandlerFunc) error {
	requestPath := strings.TrimPrefix(c.Request().URL.Path, "/")
	if strings.HasPrefix(requestPath, "api/") || requestPath == "skill" {
		return echo.NewHTTPError(http.StatusNotFound, "not found")
	}
	if requestPath == "" {
		return c.HTMLBlob(http.StatusOK, s.runtime.ui.Index())
	}

	info, err := s.runtime.ui.Stat(requestPath)
	if err == nil && !info.IsDir() {
		return fileHandler(c)
	}
	if err == nil && info.IsDir() {
		indexPath := path.Join(requestPath, "index.html")
		if nestedInfo, nestedErr := s.runtime.ui.Stat(indexPath); nestedErr == nil && !nestedInfo.IsDir() {
			c.Request().URL.Path = "/" + indexPath
			return fileHandler(c)
		}
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return c.HTMLBlob(http.StatusOK, s.runtime.ui.Index())
}

func (s *AdminServer) requireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !s.authenticated(c) {
			return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
		}
		return next(c)
	}
}

func (s *AdminServer) authenticated(c echo.Context) bool {
	ck, err := c.Cookie(adminSessionCookie)
	if err != nil {
		return false
	}
	return s.runtime.auth.Authenticated(ck.Value)
}

func (s *AdminServer) setSessionCookie(c echo.Context, token string) {
	cookie := &http.Cookie{
		Name:     adminSessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	c.SetCookie(cookie)
}

func (s *AdminServer) clearSessionCookie(c echo.Context) {
	cookie := &http.Cookie{
		Name:     adminSessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	c.SetCookie(cookie)
}

func (s *AdminServer) handleSession(c echo.Context) error {
	return c.JSON(http.StatusOK, sessionResponse{
		Authenticated:   s.authenticated(c),
		BootstrapNeeded: !s.runtime.auth.IsConfigured(),
	})
}

func (s *AdminServer) handleBootstrap(c echo.Context) error {
	if s.runtime.auth.IsConfigured() {
		return echo.NewHTTPError(http.StatusConflict, "admin password already configured")
	}

	var body passwordRequest
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if len(body.Password) < 10 {
		return echo.NewHTTPError(http.StatusBadRequest, "password must be at least 10 characters")
	}

	if err := s.runtime.BootstrapAdmin(body.Password); err != nil {
		return err
	}
	token, err := s.runtime.auth.Login(body.Password)
	if err != nil {
		return err
	}
	s.setSessionCookie(c, token)
	return c.JSON(http.StatusCreated, sessionResponse{Authenticated: true})
}

func (s *AdminServer) handleLogin(c echo.Context) error {
	var body passwordRequest
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	token, err := s.runtime.auth.Login(body.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
	}

	s.setSessionCookie(c, token)
	s.runtime.events.Add("admin.login", "info", "admin logged in", map[string]string{
		"remote": c.RealIP(),
	})
	return c.JSON(http.StatusOK, sessionResponse{Authenticated: true})
}

func (s *AdminServer) handleLogout(c echo.Context) error {
	ck, err := c.Cookie(adminSessionCookie)
	if err == nil {
		s.runtime.auth.Logout(ck.Value)
	}
	s.clearSessionCookie(c)
	return c.NoContent(http.StatusNoContent)
}

func (s *AdminServer) handleServerConfig(c echo.Context) error {
	return c.JSON(http.StatusOK, s.runtime.ServerConfig())
}

func (s *AdminServer) handleServerStatus(c echo.Context) error {
	return c.JSON(http.StatusOK, s.runtime.ServerStatus())
}

func (s *AdminServer) handlePairingCurrent(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"pairing":        s.runtime.PairingStatus(),
		"transportState": s.runtime.TransportStatus(),
	})
}

func (s *AdminServer) handlePairingInit(c echo.Context) error {
	var body pairingInitRequest
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if s.runtime.cmd.StateDir == "" {
		return echo.NewHTTPError(http.StatusConflict, "state dir is not configured")
	}

	token, err := pki.InitStateDir(s.runtime.cmd.StateDir, splitHostsCSV(body.Hosts))
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	}
	if err := s.runtime.StartTransportServer(); err != nil && !errors.Is(err, errTransportNotConfigured) {
		return err
	}

	pairing := s.runtime.PairingStatus()
	pairing.Token = token
	s.runtime.events.Add("pairing.initialized", "info", "pairing state initialized", nil)
	return c.JSON(http.StatusCreated, map[string]any{
		"pairing": pairing,
	})
}

func (s *AdminServer) handlePairingToken(c echo.Context) error {
	if s.runtime.cmd.StateDir == "" {
		return echo.NewHTTPError(http.StatusConflict, "state dir is not configured")
	}

	token, err := pki.WriteNewToken(s.runtime.cmd.StateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return echo.NewHTTPError(http.StatusConflict, "pairing state is not initialized")
		}
		return err
	}
	pairing := s.runtime.PairingStatus()
	pairing.Token = token
	s.runtime.events.Add("pairing.token_issued", "info", "pairing token issued", nil)
	return c.JSON(http.StatusCreated, map[string]any{
		"pairing": pairing,
	})
}

func (s *AdminServer) handlePolicies(c echo.Context) error {
	policies, err := admin.ListPolicyDocuments(s.runtime.cmd.PolicyDir)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"policies": policies})
}

func (s *AdminServer) handlePolicy(c echo.Context) error {
	name := filepath.Base(c.Param("name"))
	if !validPolicyFileOrDisabled(name) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid policy file name")
	}
	document, err := admin.ReadPolicyDocument(s.runtime.cmd.PolicyDir, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return echo.NewHTTPError(http.StatusNotFound, "policy not found")
		}
		return err
	}
	return c.JSON(http.StatusOK, document)
}

func (s *AdminServer) handleCreatePolicy(c echo.Context) error {
	var body policyBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := requirePolicyFileName(body.Name); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if body.Source == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "policy source is required")
	}

	path := filepath.Join(s.runtime.cmd.PolicyDir, body.Name)
	if _, err := os.Stat(path); err == nil {
		return echo.NewHTTPError(http.StatusConflict, "policy already exists")
	}
	if err := admin.ValidatePolicySource(s.runtime.cmd.PolicyDir, body.Name, body.Source); err != nil {
		return c.JSON(http.StatusBadRequest, validationResponse{
			OK:     false,
			Errors: []string{err.Error()},
		})
	}
	if err := admin.WritePolicyFileAtomically(path, body.Source); err != nil {
		return err
	}
	if err := s.runtime.ReloadPolicies(); err != nil {
		return err
	}
	document, err := admin.ReadPolicyDocument(s.runtime.cmd.PolicyDir, body.Name)
	if err != nil {
		return err
	}
	s.runtime.events.Add("policy.created", "info", "policy created: "+body.Name, map[string]string{
		"name": body.Name,
	})
	return c.JSON(http.StatusCreated, document)
}

func (s *AdminServer) handleSavePolicy(c echo.Context) error {
	name := filepath.Base(c.Param("name"))
	if !validPolicyFileOrDisabled(name) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid policy file name")
	}

	var body policyBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if body.Source == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "policy source is required")
	}
	starName := strings.TrimSuffix(name, ".disabled")
	if err := admin.ValidatePolicySource(s.runtime.cmd.PolicyDir, starName, body.Source); err != nil {
		return c.JSON(http.StatusBadRequest, validationResponse{
			OK:     false,
			Errors: []string{err.Error()},
		})
	}
	if err := admin.WritePolicyFileAtomically(filepath.Join(s.runtime.cmd.PolicyDir, name), body.Source); err != nil {
		return err
	}
	if filepath.Ext(name) == ".star" {
		if err := s.runtime.ReloadPolicies(); err != nil {
			return err
		}
	}
	document, err := admin.ReadPolicyDocument(s.runtime.cmd.PolicyDir, name)
	if err != nil {
		return err
	}
	s.runtime.events.Add("policy.saved", "info", "policy saved: "+name, map[string]string{
		"name": name,
	})
	return c.JSON(http.StatusOK, document)
}

func (s *AdminServer) handleValidatePolicy(c echo.Context) error {
	var body policyBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if !validPolicyFileOrDisabled(body.Name) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid policy file name")
	}
	if body.Source == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "policy source is required")
	}
	starName := strings.TrimSuffix(body.Name, ".disabled")
	if err := admin.ValidatePolicySource(s.runtime.cmd.PolicyDir, starName, body.Source); err != nil {
		return c.JSON(http.StatusBadRequest, validationResponse{
			OK:     false,
			Errors: []string{err.Error()},
		})
	}
	return c.JSON(http.StatusOK, validationResponse{OK: true})
}

func (s *AdminServer) handleDeletePolicy(c echo.Context) error {
	name := filepath.Base(c.Param("name"))
	if !validPolicyFileOrDisabled(name) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid policy file name")
	}
	path := filepath.Join(s.runtime.cmd.PolicyDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return echo.NewHTTPError(http.StatusNotFound, "policy not found")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if filepath.Ext(name) == ".star" {
		if err := s.runtime.ReloadPolicies(); err != nil {
			return err
		}
	}
	s.runtime.events.Add("policy.deleted", "info", "policy deleted: "+name, map[string]string{"name": name})
	return c.NoContent(http.StatusNoContent)
}

func (s *AdminServer) handleTogglePolicy(c echo.Context) error {
	name := filepath.Base(c.Param("name"))
	if err := requirePolicyFileName(name); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	dir := s.runtime.cmd.PolicyDir
	enabledPath := filepath.Join(dir, name)
	disabledPath := enabledPath + ".disabled"

	if _, err := os.Stat(enabledPath); err == nil {
		if err := os.Rename(enabledPath, disabledPath); err != nil {
			return err
		}
		if err := s.runtime.ReloadPolicies(); err != nil {
			return err
		}
		s.runtime.events.Add("policy.disabled", "info", "policy disabled: "+name, map[string]string{"name": name})
	} else if _, err := os.Stat(disabledPath); err == nil {
		if err := os.Rename(disabledPath, enabledPath); err != nil {
			return err
		}
		if err := s.runtime.ReloadPolicies(); err != nil {
			return err
		}
		s.runtime.events.Add("policy.enabled", "info", "policy enabled: "+name, map[string]string{"name": name})
	} else {
		return echo.NewHTTPError(http.StatusNotFound, "policy not found")
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *AdminServer) handleSkill(c echo.Context) error {
	pairing := s.runtime.PairingStatus()

	fingerprint := pairing.ServerFingerprint
	if fingerprint == "" {
		fingerprint = "<FINGERPRINT>"
	}

	policies, _ := admin.ListPolicyDocuments(s.runtime.cmd.PolicyDir)
	var cliNames []string
	for _, p := range policies {
		if p.Disabled {
			continue
		}
		name := strings.TrimSuffix(p.Name, ".star")
		if name == "_init" {
			continue
		}
		cliNames = append(cliNames, name)
	}

	var cliList string
	if len(cliNames) == 0 {
		cliList = "No CLIs configured yet — add policies in the admin console.\n"
	} else {
		var b strings.Builder
		for _, name := range cliNames {
			b.WriteString("- ")
			b.WriteString(name)
			b.WriteString("\n")
		}
		cliList = b.String()
	}

	setupArgs := strings.Join(cliNames, " ")
	if setupArgs == "" {
		setupArgs = "<cli-name> ..."
	}

	md := strings.NewReplacer(
		"{{fingerprint}}", fingerprint,
		"{{cliList}}", cliList,
		"{{setupArgs}}", setupArgs,
	).Replace(string(skillTemplate))

	return c.Blob(http.StatusOK, "text/markdown; charset=utf-8", []byte(md))
}

func parseIntParam(c echo.Context, name string, def int) int {
	if v := c.QueryParam(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

func (s *AdminServer) handleRuntimeEvents(c echo.Context) error {
	q := admin.EventQuery{
		MinLevel: c.QueryParam("minLevel"),
		Q:        c.QueryParam("q"),
		Limit:    parseIntParam(c, "limit", 25),
		Offset:   parseIntParam(c, "offset", 0),
	}
	page := s.runtime.events.Search(q)
	return c.JSON(http.StatusOK, map[string]any{
		"events": page.Events,
		"total":  page.Total,
	})
}

package httpapp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/benzhi/netweave/internal/domain"
	"github.com/benzhi/netweave/internal/journal"
)

const defaultMaxBody = 1 << 20

type App struct {
	store     *domain.Store
	templates *template.Template
	csrfToken string
	maxBody   int64
	ready     atomic.Bool
	stopOnce  sync.Once
	stop      chan struct{}
	previewMu sync.Mutex
	previews  map[string]rosterPreview
}

type rosterPreview struct {
	IncidentID string
	Preview    domain.RosterPreview
	ExpiresAt  time.Time
}

type PageData struct {
	Title       string
	Heading     string
	Active      string
	View        string
	CSRF        string
	Timezone    string
	EventCursor uint64
	Now         time.Time
	Incident    *domain.Incident
	Incidents   []*domain.Incident
	Summary     domain.CloseoutSummary
	Actionable  []domain.Traffic
	Blocked     []domain.Traffic
	Expired     []domain.Traffic
	Stations    []domain.Station
	Traffic     *domain.Traffic
	Message     string
	Error       string
	Form        map[string]string
	Errors      map[string]string
	Print       bool
}

func New(store *domain.Store) *App {
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		token = []byte("netweave-local-csrf-token")
	}
	a := &App{store: store, templates: template.Must(template.New("base").Funcs(template.FuncMap{
		"time": func(value time.Time, timezone string) string {
			return formatIncidentTime(value, timezone, "02 Jan 15:04")
		},
		"dateTime": func(value time.Time, timezone string) string {
			return formatIncidentTime(value, timezone, "2006-01-02 15:04:05 MST")
		},
		"join":       strings.Join,
		"value":      func(values map[string]string, key string) string { return values[key] },
		"fieldError": func(values map[string]string, key string) string { return values[key] },
		"age": func(value time.Time, now time.Time) string {
			if value.IsZero() {
				return "--"
			}
			d := now.Sub(value)
			if d < time.Minute {
				return fmt.Sprintf("%ds", int(d.Seconds()))
			}
			if d < time.Hour {
				return fmt.Sprintf("%dm", int(d.Minutes()))
			}
			return fmt.Sprintf("%dh", int(d.Hours()))
		},
		"statusClass": func(value string) string { return strings.ReplaceAll(value, "-", "_") },
		"statusLabel": func(value string) string {
			return strings.ToUpper(strings.ReplaceAll(value, "-", " "))
		},
	}).Parse(pageTemplates)), csrfToken: hex.EncodeToString(token), maxBody: defaultMaxBody, stop: make(chan struct{}), previews: make(map[string]rosterPreview)}
	a.ready.Store(true)
	return a
}

func (a *App) SetReady(value bool) { a.ready.Store(value) }

func (a *App) Stop() {
	a.stopOnce.Do(func() { close(a.stop) })
}

func (a *App) Handler() http.Handler {
	return http.HandlerFunc(a.dispatch)
}

func NewServer(store *domain.Store, address string) (*http.Server, *App) {
	app := New(store)
	server := &http.Server{
		Addr:              address,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	return server, app
}

func (a *App) dispatch(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if r.URL.Path == "/healthz" {
		a.health(w, false)
		return
	}
	if r.URL.Path == "/readyz" {
		a.health(w, true)
		return
	}
	if r.URL.Path == "/assets/app.css" {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, appCSS)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		a.dispatchAPI(w, r)
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		a.ensureCSRFCookie(w, r)
	}
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	if r.URL.Path == "/dashboard" {
		a.dashboard(w, r, "")
		return
	}
	if r.URL.Path == "/incidents/new" {
		a.newIncident(w, r)
		return
	}
	if r.URL.Path == "/incidents" && r.Method == http.MethodGet {
		a.incidents(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/incidents/") {
		a.dispatchIncident(w, r)
		return
	}
	http.NotFound(w, r)
}

func (a *App) dispatchIncident(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path)
	if len(parts) < 2 || parts[0] != "incidents" {
		http.NotFound(w, r)
		return
	}
	incidentID := parts[1]
	if len(parts) == 2 && r.Method == http.MethodGet {
		a.dashboard(w, r, incidentID)
		return
	}
	if len(parts) == 3 && parts[2] == "stations" && r.Method == http.MethodGet {
		a.stations(w, r, incidentID)
		return
	}
	if len(parts) == 4 && parts[2] == "stations" && parts[3] == "check-in" && r.Method == http.MethodPost {
		a.checkInStation(w, r, incidentID)
		return
	}
	if len(parts) == 5 && parts[2] == "stations" && parts[4] == "availability" && r.Method == http.MethodPost {
		a.updateStation(w, r, incidentID, parts[3])
		return
	}
	if len(parts) == 3 && parts[2] == "traffic" && r.Method == http.MethodGet {
		a.trafficQueue(w, r, incidentID)
		return
	}
	if len(parts) == 4 && parts[2] == "traffic" && parts[3] == "new" && (r.Method == http.MethodGet || r.Method == http.MethodPost) {
		a.newTraffic(w, r, incidentID)
		return
	}
	if len(parts) == 3 && parts[2] == "closeout" && (r.Method == http.MethodGet || r.Method == http.MethodPost) {
		a.closeout(w, r, incidentID)
		return
	}
	if len(parts) == 3 && parts[2] == "export.json" && r.Method == http.MethodGet {
		a.export(w, r, incidentID)
		return
	}
	if len(parts) == 4 && parts[2] == "print" && r.Method == http.MethodGet {
		a.printView(w, r, incidentID, parts[3])
		return
	}
	if len(parts) == 3 && parts[2] == "lifecycle" && r.Method == http.MethodPost {
		a.transitionIncident(w, r, incidentID)
		return
	}
	if len(parts) >= 4 && parts[2] == "traffic" {
		trafficID := parts[3]
		if len(parts) == 4 && r.Method == http.MethodGet {
			a.trafficDetail(w, r, incidentID, trafficID)
			return
		}
		if len(parts) == 5 && r.Method == http.MethodPost {
			a.trafficAction(w, r, incidentID, trafficID, parts[4])
			return
		}
	}
	http.NotFound(w, r)
}

func (a *App) dispatchAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/incidents" {
		if r.Method == http.MethodGet {
			a.apiListIncidents(w)
			return
		}
		if r.Method == http.MethodPost {
			a.apiCreateIncident(w, r)
			return
		}
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
		return
	}
	parts := splitPath(r.URL.Path)
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "incidents" {
		writeJSONError(w, http.StatusNotFound, "not_found", "API route was not found", nil)
		return
	}
	incidentID := parts[2]
	if len(parts) == 3 && r.Method == http.MethodGet {
		a.apiGetIncident(w, incidentID)
		return
	}
	if len(parts) == 4 && parts[3] == "transition" && r.Method == http.MethodPost {
		a.apiTransitionIncident(w, r, incidentID)
		return
	}
	if len(parts) == 4 && parts[3] == "events" && r.Method == http.MethodGet {
		a.apiEvents(w, r, incidentID)
		return
	}
	if len(parts) == 5 && parts[3] == "events" && parts[4] == "stream" && r.Method == http.MethodGet {
		a.apiEventStream(w, r, incidentID)
		return
	}
	if len(parts) == 4 && parts[3] == "stations" && r.Method == http.MethodPost {
		a.apiCheckIn(w, r, incidentID)
		return
	}
	if len(parts) == 6 && parts[3] == "stations" && parts[4] == "import" && parts[5] == "preview" && r.Method == http.MethodPost {
		a.apiRosterPreview(w, r, incidentID)
		return
	}
	if len(parts) == 6 && parts[3] == "stations" && parts[4] == "import" && parts[5] == "apply" && r.Method == http.MethodPost {
		a.apiRosterApply(w, r, incidentID)
		return
	}
	if len(parts) == 5 && parts[3] == "stations" && parts[4] == "availability" && r.Method == http.MethodPost {
		a.apiAvailability(w, r, incidentID, "")
		return
	}
	if len(parts) == 4 && parts[3] == "traffic" && r.Method == http.MethodPost {
		a.apiSubmitTraffic(w, r, incidentID)
		return
	}
	if len(parts) >= 5 && parts[3] == "traffic" {
		trafficID := parts[4]
		if len(parts) == 5 && r.Method == http.MethodGet {
			a.apiGetTraffic(w, incidentID, trafficID)
			return
		}
		if len(parts) == 6 && r.Method == http.MethodPost {
			a.apiTrafficAction(w, r, incidentID, trafficID, parts[5])
			return
		}
	}
	writeJSONError(w, http.StatusNotFound, "not_found", "API route was not found", nil)
}

func (a *App) health(w http.ResponseWriter, ready bool) {
	if ready && !a.ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (a *App) apiListIncidents(w http.ResponseWriter) {
	incidents, err := a.store.ListIncidentsFresh()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": incidents})
}

func (a *App) apiCreateIncident(w http.ResponseWriter, r *http.Request) {
	if !a.checkAPICSRF(w, r) {
		return
	}
	var input domain.IncidentInput
	if !a.decodeJSON(w, r, &input) {
		return
	}
	incident, err := a.store.CreateIncident(input, actor(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": incident})
}

func (a *App) apiGetIncident(w http.ResponseWriter, id string) {
	incident, err := a.store.GetIncident(id)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	actionable, blocked, expired := domain.QueueGroups(incident, time.Now())
	summary, _ := a.store.Summary(id)
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"incident": incident, "summary": summary, "queue": map[string]any{"actionable": actionable, "blocked": blocked, "expired": expired}}})
}

func (a *App) apiTransitionIncident(w http.ResponseWriter, r *http.Request, incidentID string) {
	if !a.checkAPICSRF(w, r) {
		return
	}
	var input struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if !a.decodeJSON(w, r, &input) {
		return
	}
	incident, err := a.store.TransitionIncident(incidentID, domain.IncidentStatus(input.Status), input.Reason, actor(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": incident})
}

func (a *App) apiCheckIn(w http.ResponseWriter, r *http.Request, incidentID string) {
	if !a.checkAPICSRF(w, r) {
		return
	}
	var input domain.StationInput
	if !a.decodeJSON(w, r, &input) {
		return
	}
	station, err := a.store.CheckInStation(incidentID, input, actor(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": station})
}

func (a *App) apiRosterPreview(w http.ResponseWriter, r *http.Request, incidentID string) {
	if !a.checkAPICSRF(w, r) {
		return
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(contentType, "text/csv") && !strings.HasPrefix(contentType, "application/octet-stream") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "roster preview expects text/csv", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, a.maxBody)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "body_too_large", err.Error(), nil)
		return
	}
	preview, err := domain.PreviewRosterCSV(data)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	token := randomToken()
	a.previewMu.Lock()
	a.previews[token] = rosterPreview{IncidentID: incidentID, Preview: preview, ExpiresAt: time.Now().Add(10 * time.Minute)}
	a.previewMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"data": preview, "preview_token": token})
}

func (a *App) apiRosterApply(w http.ResponseWriter, r *http.Request, incidentID string) {
	if !a.checkAPICSRF(w, r) {
		return
	}
	var input struct {
		PreviewToken string `json:"preview_token"`
	}
	if !a.decodeJSON(w, r, &input) {
		return
	}
	a.previewMu.Lock()
	entry, ok := a.previews[input.PreviewToken]
	if ok && (entry.IncidentID != incidentID || time.Now().After(entry.ExpiresAt)) {
		delete(a.previews, input.PreviewToken)
		ok = false
	}
	if ok {
		delete(a.previews, input.PreviewToken)
	}
	a.previewMu.Unlock()
	if !ok {
		writeDomainError(w, &domain.ValidationError{Fields: map[string]string{"preview_token": "preview token is missing or expired"}})
		return
	}
	stations, err := a.store.ApplyRoster(incidentID, entry.Preview.Rows, actor(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": stations, "applied": len(stations)})
}

func (a *App) apiAvailability(w http.ResponseWriter, r *http.Request, incidentID, stationID string) {
	if !a.checkAPICSRF(w, r) {
		return
	}
	var input struct {
		StationID       string              `json:"station_id"`
		Availability    domain.Availability `json:"availability"`
		ExpectedVersion uint64              `json:"expected_version"`
	}
	if !a.decodeJSON(w, r, &input) {
		return
	}
	if stationID == "" {
		stationID = input.StationID
	}
	station, err := a.store.UpdateStationAvailability(incidentID, stationID, input.Availability, input.ExpectedVersion, actor(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": station})
}

func (a *App) apiSubmitTraffic(w http.ResponseWriter, r *http.Request, incidentID string) {
	if !a.checkAPICSRF(w, r) {
		return
	}
	var input domain.TrafficInput
	if !a.decodeJSON(w, r, &input) {
		return
	}
	traffic, existing, err := a.store.SubmitTraffic(incidentID, input, actor(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	status := http.StatusCreated
	if existing {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"data": traffic, "idempotent": existing})
}

func (a *App) apiGetTraffic(w http.ResponseWriter, incidentID, trafficID string) {
	incident, err := a.store.GetIncident(incidentID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	traffic, ok := incident.Traffic[trafficID]
	if !ok {
		writeDomainError(w, domain.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": traffic})
}

func (a *App) apiTrafficAction(w http.ResponseWriter, r *http.Request, incidentID, trafficID, action string) {
	if !a.checkAPICSRF(w, r) {
		return
	}
	var input struct {
		StationID          string `json:"station_id"`
		ExpectedVersion    uint64 `json:"expected_version"`
		AcknowledgementKey string `json:"acknowledgement_key"`
		Final              bool   `json:"final"`
		Reason             string `json:"reason"`
		Destination        string `json:"destination"`
		Disposition        string `json:"disposition"`
	}
	if !a.decodeJSON(w, r, &input) {
		return
	}
	var traffic *domain.Traffic
	var err error
	switch action {
	case "claim":
		traffic, err = a.store.ClaimTraffic(incidentID, trafficID, input.StationID, input.ExpectedVersion, actor(r))
	case "release":
		traffic, err = a.store.ReleaseTraffic(incidentID, trafficID, input.ExpectedVersion, actor(r))
	case "transfer":
		traffic, err = a.store.TransferTraffic(incidentID, trafficID, input.StationID, input.ExpectedVersion, actor(r))
	case "start":
		traffic, err = a.store.StartTraffic(incidentID, trafficID, input.ExpectedVersion, actor(r))
	case "relay":
		traffic, err = a.store.AddRelayAttempt(incidentID, trafficID, domain.RelayInput{Destination: input.Destination, Reason: input.Reason}, input.ExpectedVersion, actor(r))
	case "fail-attempt":
		traffic, err = a.store.FailRelayAttempt(incidentID, trafficID, input.Reason, input.ExpectedVersion, actor(r))
	case "ack":
		traffic, err = a.store.AcknowledgeTraffic(incidentID, trafficID, input.AcknowledgementKey, input.Final, input.Reason, actor(r), input.ExpectedVersion)
	case "fail":
		traffic, err = a.store.FailTraffic(incidentID, trafficID, input.Reason, input.ExpectedVersion, actor(r))
	case "expire":
		traffic, err = a.store.ExpireTraffic(incidentID, trafficID, input.ExpectedVersion, actor(r))
	case "cancel":
		traffic, err = a.store.CancelTraffic(incidentID, trafficID, input.Reason, input.ExpectedVersion, actor(r))
	case "disposition":
		traffic, err = a.store.SetDisposition(incidentID, trafficID, input.Disposition, actor(r))
	default:
		writeJSONError(w, http.StatusNotFound, "not_found", "API route was not found", nil)
		return
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": traffic})
}

func (a *App) apiEvents(w http.ResponseWriter, r *http.Request, incidentID string) {
	if _, err := a.store.GetIncident(incidentID); err != nil {
		writeDomainError(w, err)
		return
	}
	cursor, err := parseCursor(r)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	events := a.store.EventsSince(cursor, incidentID)
	items := make([]eventView, 0, len(events))
	for _, event := range events {
		items = append(items, makeEventView(event))
	}
	next := cursor
	if len(items) > 0 {
		next = items[len(items)-1].Cursor
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": items, "next_cursor": next})
}

func (a *App) apiEventStream(w http.ResponseWriter, r *http.Request, incidentID string) {
	if _, err := a.store.GetIncident(incidentID); err != nil {
		writeDomainError(w, err)
		return
	}
	cursor, err := parseCursor(r)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	backlog, events, cancel := a.store.Subscribe(cursor, incidentID)
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeDomainError(w, errors.New("streaming is unavailable"))
		return
	}
	for _, event := range backlog {
		if err := writeSSE(w, makeEventView(event)); err != nil {
			return
		}
	}
	flusher.Flush()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-a.stop:
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			if err := writeSSE(w, makeEventView(event)); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			_, _ = io.WriteString(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}

type eventView struct {
	Cursor    uint64 `json:"cursor"`
	Kind      string `json:"kind"`
	Timestamp string `json:"timestamp"`
	Incident  string `json:"incident_id"`
}

func makeEventView(event journal.Event) eventView {
	return eventView{Cursor: event.Sequence, Kind: event.Kind, Timestamp: event.Timestamp, Incident: event.AggregateID}
}

func writeSSE(w io.Writer, event eventView) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: netweave\ndata: %s\n\n", event.Cursor, data)
	return err
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request, incidentID string) {
	incident, cursor, err := a.resolveIncidentView(incidentID)
	if err != nil {
		if incidentID == "" && errors.Is(err, domain.ErrNotFound) {
			a.render(w, http.StatusOK, PageData{Title: "NetWeave", Heading: "Start a net", Active: "dashboard", View: "empty", CSRF: a.csrfToken, Now: time.Now()})
			return
		}
		a.renderError(w, err)
		return
	}
	actionable, blocked, expired := domain.QueueGroups(incident, time.Now())
	summary, _ := a.store.Summary(incident.ID)
	stations := stationList(incident)
	a.render(w, http.StatusOK, PageData{Title: incident.Title, Heading: "Operations dashboard", Active: "dashboard", View: "dashboard", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Summary: summary, Actionable: actionable, Blocked: blocked, Expired: expired, Stations: stations})
}

func (a *App) incidents(w http.ResponseWriter, r *http.Request) {
	incidents, err := a.store.ListIncidentsFresh()
	if err != nil {
		a.renderError(w, err)
		return
	}
	a.render(w, http.StatusOK, PageData{Title: "Incidents", Heading: "Incident register", Active: "incidents", View: "incidents", CSRF: a.csrfToken, Now: time.Now(), Incidents: incidents})
}

func (a *App) stations(w http.ResponseWriter, r *http.Request, incidentID string) {
	incident, cursor, err := a.store.GetIncidentView(incidentID)
	if err != nil {
		a.renderError(w, err)
		return
	}
	a.render(w, http.StatusOK, PageData{Title: incident.Title + " / Stations", Heading: "Station board", Active: "stations", View: "stations", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Stations: stationList(incident)})
}

func (a *App) trafficQueue(w http.ResponseWriter, r *http.Request, incidentID string) {
	incident, cursor, err := a.store.GetIncidentView(incidentID)
	if err != nil {
		a.renderError(w, err)
		return
	}
	actionable, blocked, expired := domain.QueueGroups(incident, time.Now())
	a.render(w, http.StatusOK, PageData{Title: incident.Title + " / Traffic", Heading: "Dispatch queue", Active: "traffic", View: "traffic", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Actionable: actionable, Blocked: blocked, Expired: expired, Stations: stationList(incident)})
}

func (a *App) trafficDetail(w http.ResponseWriter, r *http.Request, incidentID, trafficID string) {
	incident, cursor, err := a.store.GetIncidentView(incidentID)
	if err != nil {
		a.renderError(w, err)
		return
	}
	traffic, ok := incident.Traffic[trafficID]
	if !ok {
		a.renderError(w, domain.ErrNotFound)
		return
	}
	a.render(w, http.StatusOK, PageData{Title: "Traffic #" + strconv.FormatUint(traffic.Sequence, 10), Heading: "Traffic detail", Active: "traffic", View: "detail", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Traffic: &traffic, Stations: stationList(incident)})
}

func (a *App) closeout(w http.ResponseWriter, r *http.Request, incidentID string) {
	incident, cursor, err := a.store.GetIncidentView(incidentID)
	if err != nil {
		a.renderError(w, err)
		return
	}
	if r.Method == http.MethodPost {
		if !a.checkHTMLCSRF(w, r) {
			return
		}
		if _, err := a.store.Closeout(incidentID, actor(r)); err != nil {
			incident, cursor, _ = a.store.GetIncidentView(incidentID)
			summary, _ := a.store.Summary(incidentID)
			a.render(w, statusFor(err), PageData{Title: incident.Title + " / Closeout", Heading: "Closeout", Active: "closeout", View: "closeout", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Summary: summary, Error: err.Error()})
			return
		}
		http.Redirect(w, r, "/incidents/"+incidentID+"/closeout", http.StatusSeeOther)
		return
	}
	summary, _ := a.store.Summary(incidentID)
	a.render(w, http.StatusOK, PageData{Title: incident.Title + " / Closeout", Heading: "Closeout", Active: "closeout", View: "closeout", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Summary: summary})
}

func (a *App) newIncident(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.render(w, http.StatusOK, PageData{Title: "New incident", Heading: "Plan a new net", Active: "dashboard", View: "new-incident", CSRF: a.csrfToken, Now: time.Now(), Form: map[string]string{"timezone": "UTC", "frequency": "146.520 MHz"}})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
		return
	}
	if !a.checkHTMLCSRF(w, r) {
		return
	}
	if err := a.parseForm(r, w); err != nil {
		a.render(w, http.StatusRequestEntityTooLarge, PageData{Title: "New incident", Heading: "Plan a new net", Active: "dashboard", View: "new-incident", CSRF: a.csrfToken, Now: time.Now(), Error: err.Error()})
		return
	}
	input := domain.IncidentInput{Title: strings.TrimSpace(r.FormValue("title")), Timezone: strings.TrimSpace(r.FormValue("timezone")), Frequency: strings.TrimSpace(r.FormValue("frequency")), ControlOperator: strings.TrimSpace(r.FormValue("control_operator"))}
	incident, err := a.store.CreateIncident(input, actor(r))
	if err != nil {
		a.render(w, statusFor(err), PageData{Title: "New incident", Heading: "Plan a new net", Active: "dashboard", View: "new-incident", CSRF: a.csrfToken, Now: time.Now(), Form: formValues(r), Errors: validationFields(err), Error: err.Error()})
		return
	}
	http.Redirect(w, r, "/incidents/"+incident.ID, http.StatusSeeOther)
}

func (a *App) checkInStation(w http.ResponseWriter, r *http.Request, incidentID string) {
	if !a.checkHTMLCSRF(w, r) {
		return
	}
	if err := a.parseForm(r, w); err != nil {
		a.renderError(w, err)
		return
	}
	input := domain.StationInput{CallSign: r.FormValue("call_sign"), Operator: r.FormValue("operator"), Location: r.FormValue("location"), Bands: splitComma(r.FormValue("bands")), Modes: splitComma(r.FormValue("modes")), Equipment: splitComma(r.FormValue("equipment")), Notes: r.FormValue("notes")}
	if _, err := a.store.CheckInStation(incidentID, input, actor(r)); err != nil {
		incident, cursor, getErr := a.store.GetIncidentView(incidentID)
		if getErr != nil {
			a.renderError(w, getErr)
			return
		}
		a.render(w, statusFor(err), PageData{Title: "Stations", Heading: "Station board", Active: "stations", View: "stations", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Stations: stationList(incident), Form: formValues(r), Errors: validationFields(err), Error: err.Error()})
		return
	}
	http.Redirect(w, r, "/incidents/"+incidentID+"/stations", http.StatusSeeOther)
}

func (a *App) updateStation(w http.ResponseWriter, r *http.Request, incidentID, stationID string) {
	if !a.checkHTMLCSRF(w, r) {
		return
	}
	if err := a.parseForm(r, w); err != nil {
		a.renderError(w, err)
		return
	}
	version, _ := strconv.ParseUint(r.FormValue("expected_version"), 10, 64)
	availability := domain.Availability(r.FormValue("availability"))
	if _, err := a.store.UpdateStationAvailability(incidentID, stationID, availability, version, actor(r)); err != nil {
		a.renderError(w, err)
		return
	}
	http.Redirect(w, r, "/incidents/"+incidentID+"/stations", http.StatusSeeOther)
}

func (a *App) newTraffic(w http.ResponseWriter, r *http.Request, incidentID string) {
	incident, cursor, err := a.store.GetIncidentView(incidentID)
	if err != nil {
		a.renderError(w, err)
		return
	}
	location := incidentLocation(incident.Timezone)
	if r.Method == http.MethodGet {
		now := time.Now()
		a.render(w, http.StatusOK, PageData{Title: incident.Title + " / New traffic", Heading: "Capture formal traffic", Active: "traffic", View: "new-traffic", CSRF: a.csrfToken, EventCursor: cursor, Now: now, Incident: incident, Form: map[string]string{"precedence": "routine", "idempotency_key": fmt.Sprintf("web-%d", now.UnixNano()), "expires_at": now.Add(2 * time.Hour).In(location).Format("2006-01-02T15:04")}})
		return
	}
	if !a.checkHTMLCSRF(w, r) {
		return
	}
	if err := a.parseForm(r, w); err != nil {
		a.renderError(w, err)
		return
	}
	received, receivedErr := parseFormTime(r.FormValue("received_at"), location)
	expires, expiresErr := parseFormTime(r.FormValue("expires_at"), location)
	if receivedErr != nil || expiresErr != nil {
		fields := make(map[string]string)
		if receivedErr != nil {
			fields["received_at"] = "received time must be a valid local date and time"
		}
		if expiresErr != nil {
			fields["expires_at"] = "expiry time must be a valid local date and time"
		}
		validation := &domain.ValidationError{Fields: fields}
		a.render(w, http.StatusUnprocessableEntity, PageData{Title: incident.Title + " / New traffic", Heading: "Capture formal traffic", Active: "traffic", View: "new-traffic", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Form: formValues(r), Errors: fields, Error: validation.Error()})
		return
	}
	input := domain.TrafficInput{Sender: r.FormValue("sender"), Recipient: r.FormValue("recipient"), Precedence: r.FormValue("precedence"), Body: r.FormValue("body"), HandlingInstructions: r.FormValue("handling_instructions"), ReceivedAt: received, ExpiresAt: expires, IdempotencyKey: r.FormValue("idempotency_key")}
	traffic, _, err := a.store.SubmitTraffic(incidentID, input, actor(r))
	if err != nil {
		a.render(w, statusFor(err), PageData{Title: incident.Title + " / New traffic", Heading: "Capture formal traffic", Active: "traffic", View: "new-traffic", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Form: formValues(r), Errors: validationFields(err), Error: err.Error()})
		return
	}
	http.Redirect(w, r, "/incidents/"+incidentID+"/traffic/"+traffic.ID, http.StatusSeeOther)
}

func (a *App) renderTrafficActionError(w http.ResponseWriter, r *http.Request, incidentID, trafficID string, err error) {
	incident, cursor, getErr := a.store.GetIncidentView(incidentID)
	if getErr != nil {
		a.renderError(w, err)
		return
	}
	traffic, ok := incident.Traffic[trafficID]
	if !ok {
		a.renderError(w, err)
		return
	}
	a.render(w, statusFor(err), PageData{Title: "Traffic #" + strconv.FormatUint(traffic.Sequence, 10), Heading: "Traffic detail", Active: "traffic", View: "detail", CSRF: a.csrfToken, EventCursor: cursor, Now: time.Now(), Incident: incident, Traffic: &traffic, Stations: stationList(incident), Form: formValues(r), Errors: validationFields(err), Error: err.Error()})
}

func (a *App) transitionIncident(w http.ResponseWriter, r *http.Request, incidentID string) {
	if !a.checkHTMLCSRF(w, r) {
		return
	}
	if err := a.parseForm(r, w); err != nil {
		a.renderError(w, err)
		return
	}
	status := domain.IncidentStatus(r.FormValue("status"))
	if _, err := a.store.TransitionIncident(incidentID, status, r.FormValue("reason"), actor(r)); err != nil {
		a.renderError(w, err)
		return
	}
	http.Redirect(w, r, "/incidents/"+incidentID, http.StatusSeeOther)
}

func (a *App) trafficAction(w http.ResponseWriter, r *http.Request, incidentID, trafficID, action string) {
	if !a.checkHTMLCSRF(w, r) {
		return
	}
	if err := a.parseForm(r, w); err != nil {
		a.renderTrafficActionError(w, r, incidentID, trafficID, err)
		return
	}
	version, _ := strconv.ParseUint(r.FormValue("expected_version"), 10, 64)
	var traffic *domain.Traffic
	var err error
	switch action {
	case "claim":
		traffic, err = a.store.ClaimTraffic(incidentID, trafficID, r.FormValue("station_id"), version, actor(r))
	case "release":
		traffic, err = a.store.ReleaseTraffic(incidentID, trafficID, version, actor(r))
	case "transfer":
		traffic, err = a.store.TransferTraffic(incidentID, trafficID, r.FormValue("station_id"), version, actor(r))
	case "start":
		traffic, err = a.store.StartTraffic(incidentID, trafficID, version, actor(r))
	case "relay":
		traffic, err = a.store.AddRelayAttempt(incidentID, trafficID, domain.RelayInput{Destination: r.FormValue("destination"), Reason: r.FormValue("reason")}, version, actor(r))
	case "fail-attempt":
		traffic, err = a.store.FailRelayAttempt(incidentID, trafficID, r.FormValue("reason"), version, actor(r))
	case "ack":
		final := r.FormValue("final") == "true"
		traffic, err = a.store.AcknowledgeTraffic(incidentID, trafficID, r.FormValue("acknowledgement_key"), final, r.FormValue("reason"), actor(r), version)
	case "fail":
		traffic, err = a.store.FailTraffic(incidentID, trafficID, r.FormValue("reason"), version, actor(r))
	case "expire":
		traffic, err = a.store.ExpireTraffic(incidentID, trafficID, version, actor(r))
	case "cancel":
		traffic, err = a.store.CancelTraffic(incidentID, trafficID, r.FormValue("reason"), version, actor(r))
	case "disposition":
		traffic, err = a.store.SetDisposition(incidentID, trafficID, r.FormValue("disposition"), actor(r))
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		a.renderTrafficActionError(w, r, incidentID, trafficID, err)
		return
	}
	http.Redirect(w, r, "/incidents/"+incidentID+"/traffic/"+traffic.ID, http.StatusSeeOther)
}

func (a *App) export(w http.ResponseWriter, r *http.Request, incidentID string) {
	data, err := a.store.Export(incidentID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+incidentID+`.json"`)
	_, _ = w.Write(data)
}

func (a *App) printView(w http.ResponseWriter, r *http.Request, incidentID, view string) {
	incident, err := a.store.GetIncident(incidentID)
	if err != nil {
		a.renderError(w, err)
		return
	}
	data := PageData{Title: incident.Title + " / Print", Heading: "Printable archive", Active: "", View: "print", CSRF: a.csrfToken, Now: time.Now(), Incident: incident, Stations: stationList(incident), Print: true}
	if view == "traffic" {
		for _, traffic := range incident.Traffic {
			data.Actionable = append(data.Actionable, traffic)
		}
		domain.SortTrafficQueue(data.Actionable, time.Now())
	}
	data.Summary, _ = a.store.Summary(incidentID)
	a.render(w, http.StatusOK, data)
}

func (a *App) render(w http.ResponseWriter, status int, data PageData) {
	if data.Now.IsZero() {
		data.Now = time.Now()
	}
	if data.CSRF == "" {
		data.CSRF = a.csrfToken
	}
	if data.Timezone == "" {
		data.Timezone = "UTC"
		if data.Incident != nil && data.Incident.Timezone != "" {
			data.Timezone = data.Incident.Timezone
		}
	}
	if data.Form == nil {
		data.Form = map[string]string{}
	}
	if data.Errors == nil {
		data.Errors = map[string]string{}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	name := "page"
	if data.Print {
		name = "print"
	}
	if err := a.templates.ExecuteTemplate(w, name, data); err != nil {
		return
	}
}

func (a *App) renderError(w http.ResponseWriter, err error) {
	status := statusFor(err)
	a.render(w, status, PageData{Title: "NetWeave", Heading: "Request could not be completed", Active: "dashboard", View: "error", CSRF: a.csrfToken, Now: time.Now(), Error: err.Error(), Errors: validationFields(err)})
}

func (a *App) resolveIncidentView(id string) (*domain.Incident, uint64, error) {
	if id != "" {
		return a.store.GetIncidentView(id)
	}
	return a.store.CurrentIncidentView()
}

func (a *App) parseForm(r *http.Request, w http.ResponseWriter) error {
	r.Body = http.MaxBytesReader(w, r.Body, a.maxBody)
	if err := r.ParseForm(); err != nil {
		return err
	}
	return nil
}

func (a *App) decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json", nil)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, a.maxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the configured limit", nil)
		} else {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		}
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the configured limit", nil)
		} else {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "request must contain one JSON value", nil)
		}
		return false
	}
	return true
}

func (a *App) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("netweave_csrf"); err != nil || cookie.Value != a.csrfToken {
		http.SetCookie(w, &http.Cookie{Name: "netweave_csrf", Value: a.csrfToken, Path: "/", SameSite: http.SameSiteLaxMode, HttpOnly: true})
	}
}

func (a *App) checkHTMLCSRF(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, a.maxBody)
	cookie, err := r.Cookie("netweave_csrf")
	if err != nil || cookie.Value != a.csrfToken {
		writeJSONError(w, http.StatusForbidden, "csrf_failed", "CSRF token is missing or invalid", nil)
		return false
	}
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the configured limit", nil)
		} else {
			writeJSONError(w, http.StatusBadRequest, "invalid_form", err.Error(), nil)
		}
		return false
	}
	if r.Form.Get("csrf_token") != a.csrfToken {
		writeJSONError(w, http.StatusForbidden, "csrf_failed", "CSRF token is missing or invalid", nil)
		return false
	}
	return true
}

func (a *App) checkAPICSRF(w http.ResponseWriter, r *http.Request) bool {
	if cookie, err := r.Cookie("netweave_csrf"); err == nil && cookie.Value != "" && r.Header.Get("X-CSRF-Token") != a.csrfToken {
		writeJSONError(w, http.StatusForbidden, "csrf_failed", "X-CSRF-Token is missing or invalid", nil)
		return false
	}
	return true
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string, fields map[string]string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "fields": fields}})
}

func writeDomainError(w http.ResponseWriter, err error) {
	status := statusFor(err)
	code := "request_failed"
	if errors.Is(err, domain.ErrNotFound) {
		code = "not_found"
	}
	if errors.Is(err, domain.ErrConflict) || errors.Is(err, domain.ErrDuplicate) || errors.Is(err, domain.ErrBusy) {
		code = "conflict"
	}
	if errors.Is(err, domain.ErrClosed) {
		code = "incident_closed"
	}
	if errors.Is(err, domain.ErrInvalid) {
		code = "invalid_request"
	}
	var validation *domain.ValidationError
	if errors.As(err, &validation) {
		code = "invalid_request"
	}
	writeJSONError(w, status, code, err.Error(), validationFields(err))
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method is not supported", nil)
}

func statusFor(err error) int {
	var validation *domain.ValidationError
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, domain.ErrConflict), errors.Is(err, domain.ErrDuplicate), errors.Is(err, domain.ErrBusy), errors.Is(err, domain.ErrExpired), errors.Is(err, domain.ErrTerminal), errors.Is(err, domain.ErrClosed):
		return http.StatusConflict
	case errors.As(err, &validation):
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadRequest
	}
}

func validationFields(err error) map[string]string {
	var validation *domain.ValidationError
	if errors.As(err, &validation) {
		return validation.Fields
	}
	return nil
}

func actor(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Operator")); value != "" {
		return value
	}
	return "net-control"
}

func randomToken() string {
	data := make([]byte, 18)
	if _, err := rand.Read(data); err != nil {
		return fmt.Sprintf("preview-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(data)
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func parseCursor(r *http.Request) (uint64, error) {
	var cursor uint64
	for _, value := range []string{strings.TrimSpace(r.URL.Query().Get("since")), strings.TrimSpace(r.Header.Get("Last-Event-ID"))} {
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, &domain.ValidationError{Fields: map[string]string{"since": "cursor must be a non-negative integer"}}
		}
		if parsed > cursor {
			cursor = parsed
		}
	}
	return cursor, nil
}

func stationList(incident *domain.Incident) []domain.Station {
	items := make([]domain.Station, 0, len(incident.Stations))
	for _, station := range incident.Stations {
		items = append(items, station)
	}
	// The board keeps urgent/unavailable rows above normal available rows.
	return sortStations(items)
}

func sortStations(items []domain.Station) []domain.Station {
	order := func(value domain.Availability) int {
		switch value {
		case domain.TemporarilyAway:
			return 0
		case domain.StationAssigned:
			return 1
		case domain.Available:
			return 2
		default:
			return 3
		}
	}
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && (order(items[j].Availability) < order(items[j-1].Availability) || (order(items[j].Availability) == order(items[j-1].Availability) && items[j].CanonicalCallSign < items[j-1].CanonicalCallSign)); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
	return items
}

func formValues(r *http.Request) map[string]string {
	values := make(map[string]string)
	for key, items := range r.Form {
		if len(items) > 0 {
			values[key] = items[0]
		}
	}
	return values
}

func splitComma(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func incidentLocation(timezone string) *time.Location {
	location, err := time.LoadLocation(strings.TrimSpace(timezone))
	if err != nil {
		return time.UTC
	}
	return location
}

func formatIncidentTime(value time.Time, timezone, layout string) string {
	if value.IsZero() {
		return "--"
	}
	return value.In(incidentLocation(timezone)).Format(layout)
}

func parseFormTime(value string, location *time.Location) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed, nil
	}
	if location == nil {
		location = time.UTC
	}
	const layout = "2006-01-02T15:04"
	parsed, err := time.ParseInLocation(layout, value, location)
	if err != nil || parsed.In(location).Format(layout) != value {
		return time.Time{}, fmt.Errorf("invalid local date and time")
	}
	for minute := -180; minute <= 180; minute++ {
		if minute == 0 {
			continue
		}
		if parsed.Add(time.Duration(minute)*time.Minute).In(location).Format(layout) == value {
			return time.Time{}, fmt.Errorf("ambiguous local date and time")
		}
	}
	return parsed, nil
}

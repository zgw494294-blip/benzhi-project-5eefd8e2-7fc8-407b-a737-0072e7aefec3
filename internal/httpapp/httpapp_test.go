package httpapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/benzhi/netweave/internal/domain"
)

func TestOperatorWorkflow(t *testing.T) {
	store, err := domain.NewStore(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := New(store).Handler()

	var created struct {
		Data domain.Incident `json:"data"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents", map[string]any{"title": "Operator workflow", "timezone": "UTC", "frequency": "146.520 MHz", "control_operator": "N0CTL"}, &created, http.StatusCreated)
	incidentID := created.Data.ID
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/transition", map[string]any{"status": "open", "reason": "net control ready"}, &struct{ Data domain.Incident }{}, http.StatusOK)

	var station struct {
		Data domain.Station `json:"data"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/stations", map[string]any{"call_sign": " k1 abc ", "operator": "Ada", "location": "North sector", "bands": []string{"2m"}, "modes": []string{"FM"}}, &station, http.StatusCreated)

	received := time.Now().UTC().Truncate(time.Second)
	var traffic struct {
		Data domain.Traffic `json:"data"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/traffic", map[string]any{"sender": "K1ABC", "recipient": "N0CTL", "precedence": "priority", "body": "All sectors checked.", "received_at": received.Format(time.RFC3339), "expires_at": received.Add(time.Hour).Format(time.RFC3339), "idempotency_key": "workflow-1"}, &traffic, http.StatusCreated)

	var claimed struct {
		Data domain.Traffic `json:"data"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/traffic/"+traffic.Data.ID+"/claim", map[string]any{"station_id": station.Data.ID, "expected_version": traffic.Data.RecordVersion}, &claimed, http.StatusOK)
	var inFlight struct {
		Data domain.Traffic `json:"data"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/traffic/"+traffic.Data.ID+"/start", map[string]any{"expected_version": claimed.Data.RecordVersion}, &inFlight, http.StatusOK)
	var failedAttempt struct {
		Data domain.Traffic `json:"data"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/traffic/"+traffic.Data.ID+"/fail-attempt", map[string]any{"reason": "relay path unavailable"}, nil, http.StatusUnprocessableEntity)
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/traffic/"+traffic.Data.ID+"/fail-attempt", map[string]any{"reason": "relay path unavailable", "expected_version": inFlight.Data.RecordVersion}, &failedAttempt, http.StatusOK)
	if failedAttempt.Data.Status != domain.Assigned || len(failedAttempt.Data.RelayAttempts) != 1 || failedAttempt.Data.RelayAttempts[0].Outcome != "failed" {
		t.Fatalf("failed relay attempt = %#v", failedAttempt.Data)
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/traffic/"+traffic.Data.ID+"/start", map[string]any{"expected_version": failedAttempt.Data.RecordVersion}, &inFlight, http.StatusOK)
	var delivered struct {
		Data domain.Traffic `json:"data"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/traffic/"+traffic.Data.ID+"/ack", map[string]any{"acknowledgement_key": "ack-1", "final": true, "reason": "read-back confirmed", "expected_version": inFlight.Data.RecordVersion}, &delivered, http.StatusOK)
	if delivered.Data.Status != domain.Delivered {
		t.Fatalf("traffic status = %s", delivered.Data.Status)
	}
	if delivered.Data.AssignedStationID != "" {
		t.Fatalf("delivered traffic still assigned to %s", delivered.Data.AssignedStationID)
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/transition", map[string]any{"status": "closing", "reason": "wind down"}, &struct{ Data domain.Incident }{}, http.StatusOK)
	var closed struct {
		Data domain.Incident `json:"data"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+incidentID+"/transition", map[string]any{"status": "closed", "reason": "all traffic reconciled"}, &closed, http.StatusOK)
	if closed.Data.Status != domain.Closed {
		t.Fatalf("incident status = %s", closed.Data.Status)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/incidents/"+incidentID+"/events?since=0", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("events status = %d", response.Code)
	}
}

func TestRosterPreviewApplyAndJSONBodyLimit(t *testing.T) {
	store, err := domain.NewStore(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	app := New(store)
	app.maxBody = 128
	handler := app.Handler()
	var created struct {
		Data domain.Incident `json:"data"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents", map[string]any{"title": "Roster", "timezone": "UTC", "frequency": "146.52", "control_operator": "N0CTL"}, &created, http.StatusCreated)
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+created.Data.ID+"/transition", map[string]any{"status": "open"}, &struct{ Data domain.Incident }{}, http.StatusOK)

	previewRequest := httptest.NewRequest(http.MethodPost, "/api/incidents/"+created.Data.ID+"/stations/import/preview", bytes.NewBufferString("call_sign,operator,location\nK1ABC,Ada,North\nBAD!,\n"))
	previewRequest.Header.Set("Content-Type", "text/csv")
	previewResponse := httptest.NewRecorder()
	handler.ServeHTTP(previewResponse, previewRequest)
	if previewResponse.Code != http.StatusOK {
		t.Fatalf("preview status = %d: %s", previewResponse.Code, previewResponse.Body.String())
	}
	var preview struct {
		Token string               `json:"preview_token"`
		Data  domain.RosterPreview `json:"data"`
	}
	if err := json.NewDecoder(previewResponse.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	if preview.Token == "" || preview.Data.ValidRows != 1 || preview.Data.InvalidRows != 1 {
		t.Fatalf("preview = %#v", preview)
	}
	var applied struct {
		Applied int `json:"applied"`
	}
	requestJSON(t, handler, http.MethodPost, "/api/incidents/"+created.Data.ID+"/stations/import/apply", map[string]any{"preview_token": preview.Token}, &applied, http.StatusCreated)
	if applied.Applied != 2-1 {
		t.Fatalf("applied = %d", applied.Applied)
	}

	tooLarge := httptest.NewRequest(http.MethodPost, "/api/incidents", bytes.NewBufferString(`{"title":"`+strings.Repeat("x", 200)+`"}`))
	tooLarge.Header.Set("Content-Type", "application/json")
	tooLargeResponse := httptest.NewRecorder()
	handler.ServeHTTP(tooLargeResponse, tooLarge)
	if tooLargeResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized JSON status = %d", tooLargeResponse.Code)
	}
}

func TestBrowserLifecycleAndIncidentNavigation(t *testing.T) {
	store, err := domain.NewStore(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	incident, err := store.CreateIncident(domain.IncidentInput{Title: "Browser lifecycle", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateIncident(domain.IncidentInput{Title: "Prior drill", Timezone: "UTC", Frequency: "146.55", ControlOperator: "N1CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	app := New(store)
	handler := app.Handler()

	response := requestHTML(t, handler, http.MethodGet, "/incidents/"+incident.ID)
	for _, want := range []string{`href="/incidents"`, `href="/incidents/new"`, `name="status" value="open"`, "Open incident"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("planned dashboard missing %q: %s", want, response.Body.String())
		}
	}
	list := requestHTML(t, handler, http.MethodGet, "/incidents")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), incident.Title) || !strings.Contains(list.Body.String(), second.Title) {
		t.Fatalf("incident list status/body = %d %s", list.Code, list.Body.String())
	}

	requestHTMLForm(t, handler, app.csrfToken, "/incidents/"+incident.ID+"/lifecycle", url.Values{"status": {"open"}}, http.StatusSeeOther)
	requestHTMLForm(t, handler, app.csrfToken, "/incidents/"+incident.ID+"/lifecycle", url.Values{"status": {"closing"}, "reason": {"wind down"}}, http.StatusSeeOther)
	requestHTMLForm(t, handler, app.csrfToken, "/incidents/"+incident.ID+"/closeout", nil, http.StatusSeeOther)
	closed := requestHTML(t, handler, http.MethodGet, "/incidents/"+incident.ID+"/closeout")
	for _, want := range []string{`name="status" value="reopened"`, `name="reason"`, "Reopen incident"} {
		if !strings.Contains(closed.Body.String(), want) {
			t.Fatalf("closed view missing %q: %s", want, closed.Body.String())
		}
	}
	requestHTMLForm(t, handler, app.csrfToken, "/incidents/"+incident.ID+"/lifecycle", url.Values{"status": {"reopened"}, "reason": {"follow-up traffic"}}, http.StatusSeeOther)
	reopened, err := store.GetIncident(incident.ID)
	if err != nil || reopened.Status != domain.Reopened {
		t.Fatalf("reopened incident = %#v, err=%v", reopened, err)
	}
}

func TestLiveUpdateScriptPreservesCursorAndRefreshesPolling(t *testing.T) {
	store, err := domain.NewStore(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	incident, err := store.CreateIncident(domain.IncidentInput{Title: "Live updates", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	response := requestHTML(t, New(store).Handler(), http.MethodGet, "/incidents/"+incident.ID)
	body := response.Body.String()
	for _, want := range []string{`data-event-cursor="1"`, "Math.max(cursor", "sessionStorage.getItem", "sessionStorage.setItem", "'?since=' + cursor", "fallback = null", "scheduleReload"} {
		if !strings.Contains(body, want) {
			t.Fatalf("live-update script missing %q: %s", want, body)
		}
	}
}

func TestBrowserTrafficUsesIncidentTimezoneAndKeepsInvalidValues(t *testing.T) {
	store, err := domain.NewStore(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	incident, err := store.CreateIncident(domain.IncidentInput{Title: "Pacific net", Timezone: "America/Los_Angeles", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	incident, err = store.TransitionIncident(incident.ID, domain.Open, "ready", "test")
	if err != nil {
		t.Fatal(err)
	}
	app := New(store)
	handler := app.Handler()
	values := url.Values{
		"sender":          {"K1ABC"},
		"recipient":       {"N0CTL"},
		"precedence":      {"priority"},
		"received_at":     {"2030-01-15T09:30"},
		"expires_at":      {"2030-01-15T10:30"},
		"idempotency_key": {"browser-timezone"},
		"body":            {"timezone boundary"},
	}
	response := requestHTMLForm(t, handler, app.csrfToken, "/incidents/"+incident.ID+"/traffic/new", values, http.StatusSeeOther)
	location := response.Header().Get("Location")
	loaded, err := store.GetIncident(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	var traffic domain.Traffic
	for _, item := range loaded.Traffic {
		traffic = item
	}
	wantReceived := time.Date(2030, 1, 15, 17, 30, 0, 0, time.UTC)
	if !traffic.ReceivedAt.Equal(wantReceived) || !traffic.ExpiresAt.Equal(wantReceived.Add(time.Hour)) {
		t.Fatalf("browser times = %s to %s", traffic.ReceivedAt, traffic.ExpiresAt)
	}
	detail := requestHTML(t, handler, http.MethodGet, location)
	if !strings.Contains(detail.Body.String(), "2030-01-15 09:30:00 PST") || !strings.Contains(detail.Body.String(), "2030-01-15 10:30:00 PST") {
		t.Fatalf("incident-local times not rendered: %s", detail.Body.String())
	}

	invalid := url.Values{
		"sender":          {"K1ABC"},
		"recipient":       {"N0CTL"},
		"precedence":      {"routine"},
		"received_at":     {"not-a-time"},
		"expires_at":      {"2030-01-15T12:00"},
		"idempotency_key": {"invalid-browser-time"},
		"body":            {"preserve this form"},
	}
	invalidResponse := requestHTMLForm(t, handler, app.csrfToken, "/incidents/"+incident.ID+"/traffic/new", invalid, http.StatusUnprocessableEntity)
	if !strings.Contains(invalidResponse.Body.String(), `type="text" name="received_at" value="not-a-time"`) || !strings.Contains(invalidResponse.Body.String(), "received time must") {
		t.Fatalf("invalid datetime was not preserved with a field error: %s", invalidResponse.Body.String())
	}
}

func TestBrowserTimeRejectsInvalidAndAmbiguousIncidentWallTimes(t *testing.T) {
	location := incidentLocation("America/Los_Angeles")
	if _, err := parseFormTime("2030-03-10T02:30", location); err == nil {
		t.Fatal("nonexistent daylight-saving wall time was accepted")
	}
	if _, err := parseFormTime("2030-11-03T01:30", location); err == nil {
		t.Fatal("ambiguous daylight-saving wall time was accepted")
	}
	parsed, err := parseFormTime("2030-01-15T09:30:00-08:00", location)
	if err != nil || !parsed.Equal(time.Date(2030, 1, 15, 17, 30, 0, 0, time.UTC)) {
		t.Fatalf("RFC3339 compatibility parse = %s, err=%v", parsed, err)
	}
}

func TestCursorUsesNewestReconnectPositionAndStaleCSRFCookieIsReplaced(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/incidents/example/events?since=4", nil)
	request.Header.Set("Last-Event-ID", "7")
	cursor, err := parseCursor(request)
	if err != nil || cursor != 7 {
		t.Fatalf("cursor = %d, err=%v", cursor, err)
	}

	store, err := domain.NewStore(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	app := New(store)
	request = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	request.AddCookie(&http.Cookie{Name: "netweave_csrf", Value: "stale-token"})
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	result := response.Result()
	defer result.Body.Close()
	var replaced bool
	for _, cookie := range result.Cookies() {
		if cookie.Name == "netweave_csrf" && cookie.Value == app.csrfToken {
			replaced = true
		}
	}
	if !replaced {
		t.Fatal("stale CSRF cookie was not replaced on GET")
	}
}

func requestJSON(t *testing.T, handler http.Handler, method, url string, input any, output any, wantStatus int) {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, url, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Operator", "test-operator")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		var detail any
		_ = json.NewDecoder(response.Body).Decode(&detail)
		t.Fatalf("%s %s status = %d, want %d: %#v", method, url, response.Code, wantStatus, detail)
	}
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

func requestHTML(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func requestHTMLForm(t *testing.T, handler http.Handler, csrfToken, path string, values url.Values, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	if values == nil {
		values = make(url.Values)
	}
	values.Set("csrf_token", csrfToken)
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: "netweave_csrf", Value: csrfToken})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("POST %s status = %d, want %d: %s", path, response.Code, wantStatus, response.Body.String())
	}
	return response
}

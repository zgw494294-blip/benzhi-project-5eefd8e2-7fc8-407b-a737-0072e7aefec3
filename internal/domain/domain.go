package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/benzhi/netweave/internal/journal"
)

type IncidentStatus string

const (
	Planned  IncidentStatus = "planned"
	Open     IncidentStatus = "open"
	Closing  IncidentStatus = "closing"
	Closed   IncidentStatus = "closed"
	Reopened IncidentStatus = "reopened"
)

type Availability string

const (
	Available       Availability = "available"
	StationAssigned Availability = "assigned"
	TemporarilyAway Availability = "temporarily-away"
	CheckedOut      Availability = "checked-out"
)

type TrafficStatus string

const (
	Queued    TrafficStatus = "queued"
	Assigned  TrafficStatus = "assigned"
	InFlight  TrafficStatus = "in-flight"
	Delivered TrafficStatus = "delivered"
	Failed    TrafficStatus = "failed"
	Expired   TrafficStatus = "expired"
	Cancelled TrafficStatus = "cancelled"
)

var (
	ErrNotFound  = errors.New("record not found")
	ErrConflict  = errors.New("record version conflict")
	ErrInvalid   = errors.New("invalid request")
	ErrLifecycle = errors.New("invalid lifecycle transition")
	ErrDuplicate = errors.New("duplicate active check-in")
	ErrBusy      = errors.New("station has active traffic")
	ErrExpired   = errors.New("traffic has expired")
	ErrTerminal  = errors.New("traffic is terminal")
	ErrClosed    = errors.New("incident is closed")
)

type ValidationError struct {
	Fields map[string]string `json:"fields"`
}

func (e *ValidationError) Error() string {
	if len(e.Fields) == 0 {
		return ErrInvalid.Error()
	}
	keys := make([]string, 0, len(e.Fields))
	for key := range e.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+": "+e.Fields[key])
	}
	return strings.Join(parts, "; ")
}

type AuditEntry struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	At            time.Time `json:"at"`
	Actor         string    `json:"actor"`
	Details       string    `json:"details,omitempty"`
	From          string    `json:"from,omitempty"`
	To            string    `json:"to,omitempty"`
	RecordID      string    `json:"record_id,omitempty"`
	RecordVersion uint64    `json:"record_version,omitempty"`
}

type StationSession struct {
	ID                string    `json:"id"`
	RawCallSign       string    `json:"raw_call_sign"`
	CanonicalCallSign string    `json:"canonical_call_sign"`
	Operator          string    `json:"operator"`
	Location          string    `json:"location"`
	CheckedInAt       time.Time `json:"checked_in_at"`
	CheckedOutAt      time.Time `json:"checked_out_at,omitempty"`
}

type Station struct {
	ID                string           `json:"id"`
	RawCallSign       string           `json:"raw_call_sign"`
	CanonicalCallSign string           `json:"canonical_call_sign"`
	Operator          string           `json:"operator"`
	Location          string           `json:"location"`
	Bands             []string         `json:"bands,omitempty"`
	Modes             []string         `json:"modes,omitempty"`
	Equipment         []string         `json:"equipment,omitempty"`
	Notes             string           `json:"notes,omitempty"`
	Availability      Availability     `json:"availability"`
	CheckInID         string           `json:"check_in_id"`
	CheckedInAt       time.Time        `json:"checked_in_at"`
	CheckedOutAt      time.Time        `json:"checked_out_at,omitempty"`
	Version           uint64           `json:"version"`
	Sessions          []StationSession `json:"sessions,omitempty"`
}

type TrafficTransition struct {
	At        time.Time     `json:"at"`
	From      TrafficStatus `json:"from"`
	To        TrafficStatus `json:"to"`
	Reason    string        `json:"reason,omitempty"`
	StationID string        `json:"station_id,omitempty"`
	Actor     string        `json:"actor,omitempty"`
}

type RelayAttempt struct {
	Number                  int       `json:"number"`
	StationID               string    `json:"station_id"`
	Destination             string    `json:"destination,omitempty"`
	StartedAt               time.Time `json:"started_at"`
	CompletedAt             time.Time `json:"completed_at,omitempty"`
	DestinationAcknowledged bool      `json:"destination_acknowledged"`
	AcknowledgementKey      string    `json:"acknowledgement_key,omitempty"`
	Outcome                 string    `json:"outcome,omitempty"`
	Reason                  string    `json:"reason,omitempty"`
}

type Traffic struct {
	ID                   string              `json:"id"`
	Sequence             uint64              `json:"sequence"`
	IdempotencyKey       string              `json:"idempotency_key"`
	RequestHash          string              `json:"request_hash,omitempty"`
	Sender               string              `json:"sender"`
	Recipient            string              `json:"recipient"`
	Precedence           string              `json:"precedence"`
	Body                 string              `json:"body"`
	HandlingInstructions string              `json:"handling_instructions,omitempty"`
	ReceivedAt           time.Time           `json:"received_at"`
	ExpiresAt            time.Time           `json:"expires_at"`
	Status               TrafficStatus       `json:"status"`
	RecordVersion        uint64              `json:"record_version"`
	AssignedStationID    string              `json:"assigned_station_id,omitempty"`
	AssignmentCheckInID  string              `json:"assignment_check_in_id,omitempty"`
	AssignedAt           time.Time           `json:"assigned_at,omitempty"`
	InFlightAt           time.Time           `json:"in_flight_at,omitempty"`
	FinalizedAt          time.Time           `json:"finalized_at,omitempty"`
	Reason               string              `json:"reason,omitempty"`
	NextLeg              int                 `json:"next_leg"`
	RelayAttempts        []RelayAttempt      `json:"relay_attempts,omitempty"`
	History              []TrafficTransition `json:"history"`
	Disposition          string              `json:"disposition,omitempty"`
	Acknowledgements     map[string]bool     `json:"acknowledgements,omitempty"`
}

type Incident struct {
	ID                  string             `json:"id"`
	Title               string             `json:"title"`
	Timezone            string             `json:"timezone"`
	Frequency           string             `json:"frequency"`
	ControlOperator     string             `json:"control_operator"`
	Status              IncidentStatus     `json:"status"`
	CreatedAt           time.Time          `json:"created_at"`
	OpenedAt            time.Time          `json:"opened_at,omitempty"`
	ClosedAt            time.Time          `json:"closed_at,omitempty"`
	ReopenedAt          time.Time          `json:"reopened_at,omitempty"`
	Version             uint64             `json:"version"`
	NextTrafficSequence uint64             `json:"next_traffic_sequence"`
	Stations            map[string]Station `json:"stations"`
	Traffic             map[string]Traffic `json:"traffic"`
	Idempotency         map[string]string  `json:"idempotency,omitempty"`
	Audit               []AuditEntry       `json:"audit"`
}

type CloseoutSummary struct {
	StationCount    int `json:"station_count"`
	CheckedOutCount int `json:"checked_out_count"`
	TrafficCount    int `json:"traffic_count"`
	DeliveredCount  int `json:"delivered_count"`
	UnresolvedCount int `json:"unresolved_count"`
	FailedCount     int `json:"failed_count"`
	ExpiredCount    int `json:"expired_count"`
	CancelledCount  int `json:"cancelled_count"`
	RelayAttempts   int `json:"relay_attempts"`
	AuditEntries    int `json:"audit_entries"`
}

type IncidentInput struct {
	Title           string `json:"title"`
	Timezone        string `json:"timezone"`
	Frequency       string `json:"frequency"`
	ControlOperator string `json:"control_operator"`
}

type StationInput struct {
	CallSign  string   `json:"call_sign"`
	Operator  string   `json:"operator"`
	Location  string   `json:"location"`
	Bands     []string `json:"bands"`
	Modes     []string `json:"modes"`
	Equipment []string `json:"equipment"`
	Notes     string   `json:"notes"`
}

type RosterRow struct {
	Line              int               `json:"line"`
	Values            StationInput      `json:"values"`
	CanonicalCallSign string            `json:"canonical_call_sign,omitempty"`
	Errors            map[string]string `json:"errors,omitempty"`
}

type RosterPreview struct {
	Columns     []string    `json:"columns"`
	Rows        []RosterRow `json:"rows"`
	ValidRows   int         `json:"valid_rows"`
	InvalidRows int         `json:"invalid_rows"`
}

type TrafficInput struct {
	Sender               string    `json:"sender"`
	Recipient            string    `json:"recipient"`
	Precedence           string    `json:"precedence"`
	Body                 string    `json:"body"`
	HandlingInstructions string    `json:"handling_instructions"`
	ReceivedAt           time.Time `json:"received_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	IdempotencyKey       string    `json:"idempotency_key"`
}

type RelayInput struct {
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
}

type Change struct {
	Incident *Incident `json:"incident"`
}

type Archive struct {
	Format      string       `json:"format"`
	ExportedAt  time.Time    `json:"exported_at"`
	Incident    *Incident    `json:"incident"`
	JournalHead journal.Head `json:"journal_head"`
}

type Store struct {
	mu          sync.RWMutex
	journal     *journal.Journal
	incidents   map[string]*Incident
	events      []journal.Event
	subscribers map[int]subscriber
	nextSub     int
	now         func() time.Time
}

type subscriber struct {
	incidentID string
	ch         chan journal.Event
}

func NewStore(path string) (*Store, error) {
	return NewStoreWithClock(path, time.Now)
}

func NewStoreWithClock(path string, now func() time.Time) (*Store, error) {
	j, err := journal.Open(path, journal.Options{Durable: true, MaxRecordBytes: 4 << 20})
	if err != nil {
		return nil, err
	}
	s := &Store{journal: j, incidents: make(map[string]*Incident), subscribers: make(map[int]subscriber), now: now}
	events := make([]journal.Event, 0)
	if err := j.ForEach(func(event journal.Event) error {
		events = append(events, event)
		return nil
	}); err != nil {
		_ = j.Close()
		return nil, err
	}
	if j.Tail().State == journal.TailIncomplete {
		if err := j.RepairTail(); err != nil {
			_ = j.Close()
			return nil, fmt.Errorf("repair incomplete journal tail: %w", err)
		}
	}
	startSequence := uint64(0)
	snapshotPath := filepath.Join(filepath.Dir(path), "snapshot.json")
	if snapshot, snapshotErr := journal.LoadSnapshot(snapshotPath); snapshotErr == nil {
		validAnchor := snapshot.Head.Sequence == 0
		if snapshot.Head.Sequence > 0 && snapshot.Head.Sequence <= uint64(len(events)) {
			anchor := events[snapshot.Head.Sequence-1]
			validAnchor = anchor.Sequence == snapshot.Head.Sequence && anchor.Checksum == snapshot.Head.Checksum
		}
		if validAnchor {
			var state struct {
				Incidents []*Incident `json:"incidents"`
			}
			if json.Unmarshal(snapshot.State, &state) == nil {
				for _, incident := range state.Incidents {
					if incident != nil && incident.ID != "" {
						normalizeIncident(incident)
						s.incidents[incident.ID] = cloneIncident(incident)
					}
				}
				startSequence = snapshot.Head.Sequence
			}
		}
	}
	if startSequence > 0 {
		for _, event := range events {
			if event.Sequence > startSequence {
				break
			}
			var change Change
			if err := json.Unmarshal(event.Payload, &change); err != nil || change.Incident == nil {
				_ = j.Close()
				return nil, fmt.Errorf("replay event %d: invalid snapshot prefix", event.Sequence)
			}
			event.AggregateID = change.Incident.ID
			event.AggregateVersion = change.Incident.Version
			s.events = append(s.events, event)
		}
	}
	for _, event := range events {
		if event.Sequence <= startSequence {
			continue
		}
		if err := applyReplayEvent(s, event); err != nil {
			_ = j.Close()
			return nil, err
		}
	}
	return s, nil
}

func applyReplayEvent(s *Store, event journal.Event) error {
	var change Change
	if err := json.Unmarshal(event.Payload, &change); err != nil {
		return fmt.Errorf("replay event %d: %w", event.Sequence, err)
	}
	if change.Incident == nil || change.Incident.ID == "" {
		return fmt.Errorf("replay event %d: missing incident", event.Sequence)
	}
	normalizeIncident(change.Incident)
	s.incidents[change.Incident.ID] = cloneIncident(change.Incident)
	event.AggregateID = change.Incident.ID
	event.AggregateVersion = change.Incident.Version
	s.events = append(s.events, event)
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sub := range s.subscribers {
		close(sub.ch)
		delete(s.subscribers, id)
	}
	return s.journal.Close()
}

func (s *Store) Journal() *journal.Journal { return s.journal }

func (s *Store) nowTime() time.Time {
	if s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}

func (s *Store) commitLocked(incident *Incident, kind, actor, details string) (journal.Event, error) {
	payload, err := json.Marshal(Change{Incident: incident})
	if err != nil {
		return journal.Event{}, err
	}
	event, err := s.journal.Append(kind, payload)
	if err != nil {
		return journal.Event{}, err
	}
	event.AggregateID = incident.ID
	event.AggregateVersion = incident.Version
	s.incidents[incident.ID] = cloneIncident(incident)
	s.events = append(s.events, event)
	for id, sub := range s.subscribers {
		if sub.incidentID != "" && sub.incidentID != event.AggregateID {
			continue
		}
		select {
		case sub.ch <- event:
		default:
			close(sub.ch)
			delete(s.subscribers, id)
		}
	}
	return event, nil
}

func (s *Store) ListIncidents() []*Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listIncidentsLocked()
}

func (s *Store) listIncidentsLocked() []*Incident {
	items := make([]*Incident, 0, len(s.incidents))
	for _, item := range s.incidents {
		items = append(items, cloneIncident(item))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items
}

func (s *Store) ListIncidentsFresh() ([]*Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reconcileExpiriesLocked(s.nowTime(), "system"); err != nil {
		return nil, err
	}
	return s.listIncidentsLocked(), nil
}

func (s *Store) GetIncident(id string) (*Incident, error) {
	incident, _, err := s.GetIncidentView(id)
	return incident, err
}

func (s *Store) GetIncidentView(id string) (*Incident, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.incidents[id]; !ok {
		return nil, 0, ErrNotFound
	}
	if err := s.reconcileIncidentExpiriesLocked(id, s.nowTime(), "system"); err != nil {
		return nil, 0, err
	}
	incident, ok := s.incidents[id]
	if !ok {
		return nil, 0, ErrNotFound
	}
	return cloneIncident(incident), s.eventCursorLocked(), nil
}

func (s *Store) CurrentIncident() (*Incident, error) {
	incident, _, err := s.CurrentIncidentView()
	return incident, err
}

func (s *Store) CurrentIncidentView() (*Incident, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reconcileExpiriesLocked(s.nowTime(), "system"); err != nil {
		return nil, 0, err
	}
	items := s.listIncidentsLocked()
	if len(items) == 0 {
		return nil, 0, ErrNotFound
	}
	return items[0], s.eventCursorLocked(), nil
}

func (s *Store) eventCursorLocked() uint64 {
	if len(s.events) == 0 {
		return 0
	}
	return s.events[len(s.events)-1].Sequence
}

func (s *Store) CreateIncident(input IncidentInput, actor string) (*Incident, error) {
	fields := map[string]string{}
	title := strings.TrimSpace(input.Title)
	if title == "" || len([]rune(title)) > 120 {
		fields["title"] = "title is required and must be at most 120 characters"
	}
	tz := strings.TrimSpace(input.Timezone)
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		fields["timezone"] = "timezone must be an IANA location"
	}
	frequency := strings.TrimSpace(input.Frequency)
	if frequency == "" || len([]rune(frequency)) > 64 {
		fields["frequency"] = "frequency is required and must be at most 64 characters"
	}
	control := strings.TrimSpace(input.ControlOperator)
	if control == "" || len([]rune(control)) > 120 {
		fields["control_operator"] = "control operator is required and must be at most 120 characters"
	}
	if len(fields) > 0 {
		return nil, &ValidationError{Fields: fields}
	}
	now := s.nowTime()
	incident := &Incident{
		ID:                  newID("INC"),
		Title:               title,
		Timezone:            tz,
		Frequency:           frequency,
		ControlOperator:     control,
		Status:              Planned,
		CreatedAt:           now,
		Version:             1,
		NextTrafficSequence: 1,
		Stations:            make(map[string]Station),
		Traffic:             make(map[string]Traffic),
		Idempotency:         make(map[string]string),
	}
	addAudit(incident, "incident.created", now, actor, "incident planned", "", "", "")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.commitLocked(incident, "incident.created", actor, "incident planned"); err != nil {
		return nil, err
	}
	return cloneIncident(incident), nil
}

func (s *Store) TransitionIncident(id string, target IncidentStatus, reason, actor string) (*Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.incidents[id]; !ok {
		return nil, ErrNotFound
	}
	if err := s.reconcileIncidentExpiriesLocked(id, s.nowTime(), "system"); err != nil {
		return nil, err
	}
	current := s.incidents[id]
	working := cloneIncident(current)
	if working.Status == target {
		return working, nil
	}
	if !validIncidentTransition(working.Status, target) {
		return nil, fmt.Errorf("%w: %s to %s", ErrLifecycle, working.Status, target)
	}
	if working.Status == Closed && target == Reopened && strings.TrimSpace(reason) == "" {
		return nil, &ValidationError{Fields: map[string]string{"reason": "reopening requires an audited reason"}}
	}
	if target == Closed {
		if err := validateCloseout(working); err != nil {
			return nil, err
		}
	}
	now := s.nowTime()
	old := working.Status
	working.Status = target
	working.Version++
	if target == Open && working.OpenedAt.IsZero() {
		working.OpenedAt = now
	}
	if target == Closed {
		working.ClosedAt = now
	}
	if target == Reopened {
		working.ReopenedAt = now
	}
	addAudit(working, "incident.transition", now, actor, reason, string(old), string(target), "")
	if _, err := s.commitLocked(working, "incident.transition", actor, reason); err != nil {
		return nil, err
	}
	return cloneIncident(working), nil
}

func (s *Store) CheckInStation(id string, input StationInput, actor string) (*Station, error) {
	canonical, err := CanonicalCallSign(input.CallSign)
	if err != nil {
		return nil, &ValidationError{Fields: map[string]string{"call_sign": err.Error()}}
	}
	fields := map[string]string{}
	if strings.TrimSpace(input.Operator) == "" {
		fields["operator"] = "operator is required"
	}
	if len([]rune(input.Operator)) > 120 {
		fields["operator"] = "operator is too long"
	}
	if len([]rune(input.Location)) > 160 {
		fields["location"] = "location is too long"
	}
	if len(fields) > 0 {
		return nil, &ValidationError{Fields: fields}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !incidentWritable(incident.Status) {
		return nil, statusError(incident.Status)
	}
	for _, station := range incident.Stations {
		if station.CanonicalCallSign == canonical && station.Availability != CheckedOut {
			return nil, ErrDuplicate
		}
	}
	working := cloneIncident(incident)
	now := s.nowTime()
	station := Station{
		ID:                newID("STN"),
		RawCallSign:       strings.TrimSpace(input.CallSign),
		CanonicalCallSign: canonical,
		Operator:          strings.TrimSpace(input.Operator),
		Location:          strings.TrimSpace(input.Location),
		Bands:             cleanList(input.Bands),
		Modes:             cleanList(input.Modes),
		Equipment:         cleanList(input.Equipment),
		Notes:             strings.TrimSpace(input.Notes),
		Availability:      Available,
		CheckInID:         newID("CHK"),
		CheckedInAt:       now,
		Version:           1,
	}
	station.Sessions = []StationSession{{ID: station.CheckInID, RawCallSign: station.RawCallSign, CanonicalCallSign: canonical, Operator: station.Operator, Location: station.Location, CheckedInAt: now}}
	working.Stations[station.ID] = station
	working.Version++
	addAudit(working, "station.checked_in", now, actor, station.CanonicalCallSign, "", "available", station.ID)
	if _, err := s.commitLocked(working, "station.checked_in", actor, station.CanonicalCallSign); err != nil {
		return nil, err
	}
	return cloneStation(&station), nil
}

func PreviewRosterCSV(data []byte) (RosterPreview, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	rows, err := reader.ReadAll()
	if err != nil {
		return RosterPreview{}, &ValidationError{Fields: map[string]string{"csv": err.Error()}}
	}
	if len(rows) == 0 {
		return RosterPreview{}, &ValidationError{Fields: map[string]string{"csv": "CSV must include a header and at least one row"}}
	}
	if len(rows) < 2 {
		return RosterPreview{}, &ValidationError{Fields: map[string]string{"csv": "CSV must include at least one data row after the header"}}
	}
	indexes := make(map[string]int)
	columns := make([]string, 0, len(rows[0]))
	for index, value := range rows[0] {
		key := strings.ToLower(strings.TrimSpace(value))
		key = strings.ReplaceAll(key, " ", "_")
		indexes[key] = index
		columns = append(columns, key)
	}
	for _, required := range []string{"call_sign", "operator"} {
		if _, ok := indexes[required]; !ok {
			return RosterPreview{}, &ValidationError{Fields: map[string]string{"csv": "missing required column " + required}}
		}
	}
	preview := RosterPreview{Columns: columns, Rows: make([]RosterRow, 0, len(rows)-1)}
	for offset, values := range rows[1:] {
		line := offset + 2
		if allBlank(values) {
			continue
		}
		row := RosterRow{Line: line, Values: StationInput{CallSign: rosterValue(values, indexes, "call_sign"), Operator: rosterValue(values, indexes, "operator"), Location: rosterValue(values, indexes, "location"), Bands: splitRosterList(rosterValue(values, indexes, "bands")), Modes: splitRosterList(rosterValue(values, indexes, "modes")), Equipment: splitRosterList(rosterValue(values, indexes, "equipment")), Notes: rosterValue(values, indexes, "notes")}}
		row.Errors = validateRosterStation(row.Values)
		if len(row.Errors) == 0 {
			row.CanonicalCallSign, _ = CanonicalCallSign(row.Values.CallSign)
			preview.ValidRows++
		} else {
			preview.InvalidRows++
		}
		preview.Rows = append(preview.Rows, row)
	}
	return preview, nil
}

func (s *Store) ApplyRoster(incidentID string, rows []RosterRow, actor string) ([]Station, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[incidentID]
	if !ok {
		return nil, ErrNotFound
	}
	if !incidentWritable(incident.Status) {
		return nil, statusError(incident.Status)
	}
	working := cloneIncident(incident)
	seen := make(map[string]bool)
	for _, row := range rows {
		if len(row.Errors) > 0 {
			continue
		}
		canonical, err := CanonicalCallSign(row.Values.CallSign)
		if err != nil {
			return nil, fmt.Errorf("%w: CSV row %d: %v", ErrInvalid, row.Line, err)
		}
		if seen[canonical] {
			return nil, fmt.Errorf("%w: duplicate call sign %s in CSV", ErrDuplicate, canonical)
		}
		seen[canonical] = true
		for _, station := range working.Stations {
			if station.CanonicalCallSign == canonical && station.Availability != CheckedOut {
				return nil, fmt.Errorf("%w: %s", ErrDuplicate, canonical)
			}
		}
	}
	now := s.nowTime()
	created := make([]Station, 0, len(rows))
	for _, row := range rows {
		if len(row.Errors) > 0 {
			continue
		}
		canonical, _ := CanonicalCallSign(row.Values.CallSign)
		station := Station{ID: newID("STN"), RawCallSign: strings.TrimSpace(row.Values.CallSign), CanonicalCallSign: canonical, Operator: strings.TrimSpace(row.Values.Operator), Location: strings.TrimSpace(row.Values.Location), Bands: cleanList(row.Values.Bands), Modes: cleanList(row.Values.Modes), Equipment: cleanList(row.Values.Equipment), Notes: strings.TrimSpace(row.Values.Notes), Availability: Available, CheckInID: newID("CHK"), CheckedInAt: now, Version: 1}
		station.Sessions = []StationSession{{ID: station.CheckInID, RawCallSign: station.RawCallSign, CanonicalCallSign: canonical, Operator: station.Operator, Location: station.Location, CheckedInAt: now}}
		working.Stations[station.ID] = station
		working.Version++
		addAudit(working, "station.checked_in", now, actor, canonical+" from CSV", "", "available", station.ID)
		created = append(created, station)
	}
	if len(created) == 0 {
		return nil, &ValidationError{Fields: map[string]string{"csv": "preview contains no rows"}}
	}
	if _, err := s.commitLocked(working, "station.roster_import", actor, fmt.Sprintf("%d stations", len(created))); err != nil {
		return nil, err
	}
	return created, nil
}

func (s *Store) UpdateStationAvailability(incidentID, stationID string, availability Availability, expectedVersion uint64, actor string) (*Station, error) {
	if availability != Available && availability != TemporarilyAway && availability != CheckedOut && availability != StationAssigned {
		return nil, &ValidationError{Fields: map[string]string{"availability": "unsupported availability"}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[incidentID]
	if !ok {
		return nil, ErrNotFound
	}
	if incident.Status == Closed {
		return nil, ErrClosed
	}
	station, ok := incident.Stations[stationID]
	if !ok {
		return nil, ErrNotFound
	}
	if expectedVersion > 0 && station.Version != expectedVersion {
		return nil, ErrConflict
	}
	if availability == StationAssigned {
		return nil, &ValidationError{Fields: map[string]string{"availability": "assigned is managed by traffic claims"}}
	}
	if station.Availability == CheckedOut && availability != CheckedOut {
		return nil, fmt.Errorf("%w: check in a new session before making a checked-out station available", ErrConflict)
	}
	if trafficID := activeTrafficForStation(incident, stationID); trafficID != "" {
		return nil, fmt.Errorf("%w: %s", ErrBusy, trafficID)
	}
	working := cloneIncident(incident)
	updated := working.Stations[stationID]
	now := s.nowTime()
	old := updated.Availability
	updated.Availability = availability
	updated.Version++
	if availability == CheckedOut {
		updated.CheckedOutAt = now
		for i := range updated.Sessions {
			if updated.Sessions[i].ID == updated.CheckInID && updated.Sessions[i].CheckedOutAt.IsZero() {
				updated.Sessions[i].CheckedOutAt = now
			}
		}
	}
	working.Stations[stationID] = updated
	working.Version++
	addAudit(working, "station.availability", now, actor, string(old)+" -> "+string(availability), string(old), string(availability), stationID)
	if _, err := s.commitLocked(working, "station.availability", actor, string(availability)); err != nil {
		return nil, err
	}
	return cloneStation(&updated), nil
}

func (s *Store) SubmitTraffic(incidentID string, input TrafficInput, actor string) (*Traffic, bool, error) {
	fields := validateTrafficInput(input)
	if len(fields) > 0 {
		return nil, false, &ValidationError{Fields: fields}
	}
	requestHash := hashTrafficInput(input)
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[incidentID]
	if !ok {
		return nil, false, ErrNotFound
	}
	if !incidentWritable(incident.Status) {
		if prior, exists := incident.Idempotency[input.IdempotencyKey]; exists {
			if traffic, ok := incident.Traffic[prior]; ok && sameTrafficRequest(traffic, input) {
				return cloneTraffic(&traffic), true, nil
			}
		}
		return nil, false, statusError(incident.Status)
	}
	if prior, exists := incident.Idempotency[input.IdempotencyKey]; exists {
		traffic, ok := incident.Traffic[prior]
		if !ok {
			return nil, false, fmt.Errorf("%w: idempotency record missing", ErrConflict)
		}
		if traffic.IdempotencyKey != input.IdempotencyKey || !sameTrafficRequest(traffic, input) {
			return nil, false, fmt.Errorf("%w: idempotency key reused with different payload", ErrConflict)
		}
		return cloneTraffic(&traffic), true, nil
	}
	working := cloneIncident(incident)
	now := s.nowTime()
	received := input.ReceivedAt.UTC()
	if received.IsZero() {
		received = now
	}
	traffic := Traffic{
		ID:                   newID("TRF"),
		Sequence:             working.NextTrafficSequence,
		IdempotencyKey:       input.IdempotencyKey,
		RequestHash:          requestHash,
		Sender:               strings.TrimSpace(input.Sender),
		Recipient:            strings.TrimSpace(input.Recipient),
		Precedence:           normalizePrecedence(input.Precedence),
		Body:                 input.Body,
		HandlingInstructions: strings.TrimSpace(input.HandlingInstructions),
		ReceivedAt:           received,
		ExpiresAt:            input.ExpiresAt.UTC(),
		Status:               Queued,
		RecordVersion:        1,
		Acknowledgements:     make(map[string]bool),
		History:              []TrafficTransition{{At: now, To: Queued, Actor: actor}},
	}
	working.Traffic[traffic.ID] = traffic
	working.Idempotency[input.IdempotencyKey] = traffic.ID
	working.NextTrafficSequence++
	working.Version++
	addAudit(working, "traffic.queued", now, actor, "traffic queued", "", string(Queued), traffic.ID)
	if _, err := s.commitLocked(working, "traffic.queued", actor, traffic.ID); err != nil {
		return nil, false, err
	}
	return cloneTraffic(&traffic), false, nil
}

func (s *Store) ClaimTraffic(incidentID, trafficID, stationID string, expectedVersion uint64, actor string) (*Traffic, error) {
	return s.mutateTraffic(incidentID, trafficID, expectedVersion, actor, "traffic.assigned", func(working *Incident, traffic *Traffic, now time.Time) error {
		station, ok := working.Stations[stationID]
		if !ok {
			return ErrNotFound
		}
		if traffic.Status == Assigned && traffic.AssignedStationID == stationID {
			return nil
		}
		if traffic.Status != Queued {
			return fmt.Errorf("%w: traffic must be queued", ErrConflict)
		}
		if !now.Before(traffic.ExpiresAt) {
			return expireTraffic(working, traffic, traffic.ExpiresAt, actor, "expiry boundary")
		}
		if station.Availability != Available {
			return fmt.Errorf("%w: station is %s", ErrConflict, station.Availability)
		}
		if activeTrafficForStation(working, stationID) != "" {
			return ErrBusy
		}
		traffic.AssignedStationID = stationID
		traffic.AssignmentCheckInID = station.CheckInID
		traffic.AssignedAt = now
		transitionTraffic(traffic, Assigned, now, "claim", stationID, actor)
		station.Availability = StationAssigned
		station.Version++
		working.Stations[stationID] = station
		working.Version++
		addAudit(working, "traffic.assigned", now, actor, "assigned to "+station.CanonicalCallSign, string(Queued), string(Assigned), traffic.ID)
		return nil
	})
}

func (s *Store) ReleaseTraffic(incidentID, trafficID string, expectedVersion uint64, actor string) (*Traffic, error) {
	return s.mutateTraffic(incidentID, trafficID, expectedVersion, actor, "traffic.released", func(working *Incident, traffic *Traffic, now time.Time) error {
		if traffic.Status != Assigned {
			return fmt.Errorf("%w: only assigned traffic can be released", ErrConflict)
		}
		oldStation := traffic.AssignedStationID
		traffic.AssignedStationID = ""
		traffic.AssignmentCheckInID = ""
		traffic.AssignedAt = time.Time{}
		transitionTraffic(traffic, Queued, now, "release", oldStation, actor)
		if station, ok := working.Stations[oldStation]; ok {
			station.Availability = Available
			station.Version++
			working.Stations[oldStation] = station
		}
		working.Version++
		addAudit(working, "traffic.released", now, actor, "returned to queue", string(Assigned), string(Queued), traffic.ID)
		return nil
	})
}

func (s *Store) TransferTraffic(incidentID, trafficID, stationID string, expectedVersion uint64, actor string) (*Traffic, error) {
	return s.mutateTraffic(incidentID, trafficID, expectedVersion, actor, "traffic.transferred", func(working *Incident, traffic *Traffic, now time.Time) error {
		if traffic.Status != Assigned && traffic.Status != InFlight {
			return fmt.Errorf("%w: only active traffic can be transferred", ErrConflict)
		}
		newStation, ok := working.Stations[stationID]
		if !ok {
			return ErrNotFound
		}
		if newStation.Availability != Available || activeTrafficForStation(working, stationID) != "" {
			return fmt.Errorf("%w: destination station is unavailable", ErrConflict)
		}
		oldStationID := traffic.AssignedStationID
		oldStatus := traffic.Status
		if oldStation, ok := working.Stations[oldStationID]; ok {
			oldStation.Availability = Available
			oldStation.Version++
			working.Stations[oldStationID] = oldStation
		}
		traffic.AssignedStationID = stationID
		traffic.AssignmentCheckInID = newStation.CheckInID
		traffic.AssignedAt = now
		if oldStatus == InFlight {
			completeOpenRelayAttempt(traffic, now, "transferred", "traffic transferred")
			traffic.InFlightAt = time.Time{}
			transitionTraffic(traffic, Assigned, now, "transfer", stationID, actor)
		}
		newStation.Availability = StationAssigned
		newStation.Version++
		working.Stations[stationID] = newStation
		working.Version++
		addAudit(working, "traffic.transferred", now, actor, oldStationID+" -> "+stationID, string(oldStatus), string(traffic.Status), traffic.ID)
		return nil
	})
}

func (s *Store) StartTraffic(incidentID, trafficID string, expectedVersion uint64, actor string) (*Traffic, error) {
	return s.mutateTraffic(incidentID, trafficID, expectedVersion, actor, "traffic.in_flight", func(working *Incident, traffic *Traffic, now time.Time) error {
		if traffic.Status != Assigned {
			return fmt.Errorf("%w: only assigned traffic can start", ErrConflict)
		}
		traffic.InFlightAt = now
		traffic.RelayAttempts = append(traffic.RelayAttempts, RelayAttempt{Number: len(traffic.RelayAttempts) + 1, StationID: traffic.AssignedStationID, StartedAt: now})
		transitionTraffic(traffic, InFlight, now, "started", traffic.AssignedStationID, actor)
		working.Version++
		addAudit(working, "traffic.in_flight", now, actor, "relay started", string(Assigned), string(InFlight), traffic.ID)
		return nil
	})
}

func (s *Store) AddRelayAttempt(incidentID, trafficID string, input RelayInput, expectedVersion uint64, actor string) (*Traffic, error) {
	return s.mutateTraffic(incidentID, trafficID, expectedVersion, actor, "traffic.relay_appended", func(working *Incident, traffic *Traffic, now time.Time) error {
		if traffic.Status != Assigned && traffic.Status != InFlight {
			return fmt.Errorf("%w: terminal traffic cannot relay", ErrTerminal)
		}
		if traffic.Status == InFlight && len(traffic.RelayAttempts) > 0 && traffic.RelayAttempts[len(traffic.RelayAttempts)-1].CompletedAt.IsZero() {
			return fmt.Errorf("%w: the current relay attempt is still in progress", ErrConflict)
		}
		traffic.RelayAttempts = append(traffic.RelayAttempts, RelayAttempt{Number: len(traffic.RelayAttempts) + 1, StationID: traffic.AssignedStationID, Destination: strings.TrimSpace(input.Destination), StartedAt: now, Reason: strings.TrimSpace(input.Reason)})
		old := traffic.Status
		traffic.InFlightAt = now
		if traffic.Status == Assigned {
			transitionTraffic(traffic, InFlight, now, "relay attempt started", traffic.AssignedStationID, actor)
		}
		working.Version++
		addAudit(working, "traffic.relay_appended", now, actor, "relay attempt started", string(old), string(traffic.Status), traffic.ID)
		return nil
	})
}

func (s *Store) FailRelayAttempt(incidentID, trafficID, reason string, expectedVersion uint64, actor string) (*Traffic, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len([]rune(reason)) > 240 {
		return nil, &ValidationError{Fields: map[string]string{"reason": "a relay failure reason between 1 and 240 characters is required"}}
	}
	if expectedVersion == 0 {
		return nil, &ValidationError{Fields: map[string]string{"expected_version": "the current record version is required"}}
	}
	return s.mutateTraffic(incidentID, trafficID, expectedVersion, actor, "traffic.relay_failed", func(working *Incident, traffic *Traffic, now time.Time) error {
		if traffic.Status != InFlight {
			return fmt.Errorf("%w: only in-flight traffic has a relay attempt to fail", ErrConflict)
		}
		if len(traffic.RelayAttempts) == 0 {
			return fmt.Errorf("%w: no relay attempt is in progress", ErrConflict)
		}
		last := &traffic.RelayAttempts[len(traffic.RelayAttempts)-1]
		if !last.CompletedAt.IsZero() {
			return fmt.Errorf("%w: the current relay attempt is already complete", ErrConflict)
		}
		last.CompletedAt = now
		last.DestinationAcknowledged = false
		last.Outcome = "failed"
		last.Reason = reason
		traffic.InFlightAt = time.Time{}
		transitionTraffic(traffic, Assigned, now, reason, traffic.AssignedStationID, actor)
		working.Version++
		addAudit(working, "traffic.relay_failed", now, actor, reason, string(InFlight), string(Assigned), traffic.ID)
		return nil
	})
}

func (s *Store) AcknowledgeTraffic(incidentID, trafficID, acknowledgementKey string, final bool, reason, actor string, expectedVersion uint64) (*Traffic, error) {
	if acknowledgementKey == "" {
		return nil, &ValidationError{Fields: map[string]string{"acknowledgement_key": "acknowledgement key is required"}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[incidentID]
	if !ok {
		return nil, ErrNotFound
	}
	if incident.Status == Closed {
		return nil, ErrClosed
	}
	current, ok := incident.Traffic[trafficID]
	if !ok {
		return nil, ErrNotFound
	}
	if current.Acknowledgements != nil && current.Acknowledgements[acknowledgementKey] {
		copy := current
		return cloneTraffic(&copy), nil
	}
	if expectedVersion == 0 {
		return nil, &ValidationError{Fields: map[string]string{"expected_version": "the current record version is required"}}
	}
	if expectedVersion > 0 && current.RecordVersion != expectedVersion {
		return nil, ErrConflict
	}
	now := s.nowTime()
	if !IsTerminal(current.Status) && !now.Before(current.ExpiresAt) {
		working := cloneIncident(incident)
		updated := working.Traffic[trafficID]
		_ = expireTraffic(working, &updated, updated.ExpiresAt, actor, "expiry boundary")
		working.Traffic[trafficID] = updated
		if _, err := s.commitLocked(working, "traffic.expired", actor, "expiry boundary"); err != nil {
			return nil, err
		}
		return nil, ErrExpired
	}
	if current.Status != InFlight {
		return nil, fmt.Errorf("%w: acknowledgement cannot revive %s", ErrTerminal, current.Status)
	}
	if len(current.RelayAttempts) == 0 || !current.RelayAttempts[len(current.RelayAttempts)-1].CompletedAt.IsZero() {
		return nil, fmt.Errorf("%w: no relay attempt is in progress", ErrConflict)
	}
	working := cloneIncident(incident)
	traffic := working.Traffic[trafficID]
	if traffic.Acknowledgements == nil {
		traffic.Acknowledgements = make(map[string]bool)
	}
	traffic.Acknowledgements[acknowledgementKey] = true
	if len(traffic.RelayAttempts) > 0 {
		last := &traffic.RelayAttempts[len(traffic.RelayAttempts)-1]
		last.CompletedAt = now
		last.DestinationAcknowledged = true
		last.AcknowledgementKey = acknowledgementKey
		last.Outcome = map[bool]string{true: "delivered", false: "relay-complete"}[final]
		last.Reason = strings.TrimSpace(reason)
	}
	old := traffic.Status
	stationID := traffic.AssignedStationID
	if final {
		traffic.FinalizedAt = now
		traffic.Reason = strings.TrimSpace(reason)
		traffic.AssignedStationID = ""
		traffic.AssignmentCheckInID = ""
		traffic.AssignedAt = time.Time{}
		traffic.InFlightAt = time.Time{}
		transitionTraffic(&traffic, Delivered, now, "destination acknowledgement", stationID, actor)
	} else {
		traffic.NextLeg++
		traffic.AssignedStationID = ""
		traffic.AssignmentCheckInID = ""
		traffic.AssignedAt = time.Time{}
		traffic.InFlightAt = time.Time{}
		transitionTraffic(&traffic, Queued, now, "relay leg acknowledged", stationID, actor)
	}
	if station, ok := working.Stations[stationID]; ok {
		station.Availability = Available
		station.Version++
		working.Stations[stationID] = station
	}
	traffic.RecordVersion++
	working.Traffic[trafficID] = traffic
	working.Version++
	addAudit(working, "traffic.acknowledged", now, actor, reason, string(old), string(traffic.Status), traffic.ID)
	if _, err := s.commitLocked(working, "traffic.acknowledged", actor, traffic.ID); err != nil {
		return nil, err
	}
	return cloneTraffic(&traffic), nil
}

func (s *Store) FailTraffic(incidentID, trafficID, reason string, expectedVersion uint64, actor string) (*Traffic, error) {
	return s.finishTraffic(incidentID, trafficID, Failed, reason, expectedVersion, actor)
}

func (s *Store) ExpireTraffic(incidentID, trafficID string, expectedVersion uint64, actor string) (*Traffic, error) {
	return s.finishTraffic(incidentID, trafficID, Expired, "expiry boundary", expectedVersion, actor)
}

func (s *Store) CancelTraffic(incidentID, trafficID, reason string, expectedVersion uint64, actor string) (*Traffic, error) {
	return s.finishTraffic(incidentID, trafficID, Cancelled, reason, expectedVersion, actor)
}

func (s *Store) finishTraffic(incidentID, trafficID string, target TrafficStatus, reason string, expectedVersion uint64, actor string) (*Traffic, error) {
	return s.mutateTraffic(incidentID, trafficID, expectedVersion, actor, "traffic."+string(target), func(working *Incident, traffic *Traffic, now time.Time) error {
		if traffic.Status == Delivered || traffic.Status == Failed || traffic.Status == Expired || traffic.Status == Cancelled {
			if traffic.Status == target {
				return nil
			}
			return ErrTerminal
		}
		old := traffic.Status
		stationID := traffic.AssignedStationID
		transitionAt := now
		if target == Expired {
			transitionAt = traffic.ExpiresAt
		}
		if old == InFlight {
			completeOpenRelayAttempt(traffic, transitionAt, string(target), reason)
		}
		traffic.Reason = strings.TrimSpace(reason)
		traffic.FinalizedAt = transitionAt
		traffic.AssignedStationID = ""
		traffic.AssignmentCheckInID = ""
		traffic.AssignedAt = time.Time{}
		traffic.InFlightAt = time.Time{}
		transitionTraffic(traffic, target, transitionAt, reason, stationID, actor)
		if station, ok := working.Stations[stationID]; ok {
			station.Availability = Available
			station.Version++
			working.Stations[stationID] = station
		}
		working.Version++
		addAudit(working, "traffic."+string(target), transitionAt, actor, reason, string(old), string(target), traffic.ID)
		return nil
	})
}

func (s *Store) SetDisposition(incidentID, trafficID, disposition, actor string) (*Traffic, error) {
	disposition = strings.TrimSpace(disposition)
	if disposition == "" || len([]rune(disposition)) > 240 {
		return nil, &ValidationError{Fields: map[string]string{"disposition": "a disposition between 1 and 240 characters is required"}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[incidentID]
	if !ok {
		return nil, ErrNotFound
	}
	if incident.Status == Closed {
		return nil, ErrClosed
	}
	_, ok = incident.Traffic[trafficID]
	if !ok {
		return nil, ErrNotFound
	}
	working := cloneIncident(incident)
	updated := working.Traffic[trafficID]
	updated.Disposition = disposition
	updated.RecordVersion++
	working.Traffic[trafficID] = updated
	working.Version++
	now := s.nowTime()
	addAudit(working, "traffic.disposition", now, actor, disposition, "", "", trafficID)
	if _, err := s.commitLocked(working, "traffic.disposition", actor, disposition); err != nil {
		return nil, err
	}
	return cloneTraffic(&updated), nil
}

func (s *Store) mutateTraffic(incidentID, trafficID string, expectedVersion uint64, actor, kind string, mutate func(*Incident, *Traffic, time.Time) error) (*Traffic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[incidentID]
	if !ok {
		return nil, ErrNotFound
	}
	if incident.Status == Closed {
		return nil, ErrClosed
	}
	if incident.Status == Closing && !closingTrafficMutation(kind) {
		return nil, fmt.Errorf("%w: %s is not allowed while closing", ErrConflict, kind)
	}
	traffic, ok := incident.Traffic[trafficID]
	if !ok {
		return nil, ErrNotFound
	}
	if expectedVersion == 0 {
		return nil, &ValidationError{Fields: map[string]string{"expected_version": "the current record version is required"}}
	}
	if expectedVersion > 0 && traffic.RecordVersion != expectedVersion {
		return nil, ErrConflict
	}
	working := cloneIncident(incident)
	updated := working.Traffic[trafficID]
	now := s.nowTime()
	if kind == "traffic.expired" && now.Before(updated.ExpiresAt) {
		return nil, fmt.Errorf("%w: expiry time has not arrived", ErrConflict)
	}
	if kind != "traffic.expired" && !IsTerminal(updated.Status) && !now.Before(updated.ExpiresAt) {
		if err := expireTraffic(working, &updated, updated.ExpiresAt, actor, "expiry boundary"); err != nil && !errors.Is(err, ErrExpired) {
			return nil, err
		}
		working.Traffic[trafficID] = updated
		if _, err := s.commitLocked(working, "traffic.expired", actor, "expiry boundary"); err != nil {
			return nil, err
		}
		return nil, ErrExpired
	}
	if err := mutate(working, &updated, now); err != nil {
		if errors.Is(err, ErrExpired) {
			working.Traffic[trafficID] = updated
			if _, commitErr := s.commitLocked(working, "traffic.expired", actor, "expiry boundary"); commitErr != nil {
				return nil, commitErr
			}
		}
		return nil, err
	}
	if reflect.DeepEqual(working, incident) {
		copy := traffic
		return cloneTraffic(&copy), nil
	}
	if updated.RecordVersion == traffic.RecordVersion {
		updated.RecordVersion++
	}
	working.Traffic[trafficID] = updated
	if _, err := s.commitLocked(working, kind, actor, trafficID); err != nil {
		return nil, err
	}
	return cloneTraffic(&updated), nil
}

func closingTrafficMutation(kind string) bool {
	switch kind {
	case "traffic.acknowledged", "traffic.relay_failed", "traffic.failed", "traffic.expired", "traffic.cancelled":
		return true
	default:
		return false
	}
}

func IsTerminal(status TrafficStatus) bool {
	return status == Delivered || status == Failed || status == Expired || status == Cancelled
}

func (s *Store) Closeout(incidentID, actor string) (*Incident, error) {
	return s.TransitionIncident(incidentID, Closed, "closeout confirmed", actor)
}

func (s *Store) Summary(incidentID string) (CloseoutSummary, error) {
	incident, err := s.GetIncident(incidentID)
	if err != nil {
		return CloseoutSummary{}, err
	}
	var summary CloseoutSummary
	summary.StationCount = len(incident.Stations)
	summary.AuditEntries = len(incident.Audit)
	for _, station := range incident.Stations {
		if station.Availability == CheckedOut {
			summary.CheckedOutCount++
		}
	}
	for _, traffic := range incident.Traffic {
		summary.TrafficCount++
		summary.RelayAttempts += len(traffic.RelayAttempts)
		switch traffic.Status {
		case Delivered:
			summary.DeliveredCount++
		case Failed:
			summary.FailedCount++
		case Expired:
			summary.ExpiredCount++
		case Cancelled:
			summary.CancelledCount++
		default:
			summary.UnresolvedCount++
		}
	}
	return summary, nil
}

func (s *Store) Export(incidentID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.incidents[incidentID]; !ok {
		return nil, ErrNotFound
	}
	if err := s.reconcileIncidentExpiriesLocked(incidentID, s.nowTime(), "system"); err != nil {
		return nil, err
	}
	incident := s.incidents[incidentID]
	archive := Archive{Format: "netweave-incident-v1", ExportedAt: s.nowTime(), Incident: cloneIncident(incident), JournalHead: s.journal.Head()}
	return json.MarshalIndent(archive, "", "  ")
}

func (s *Store) SaveSnapshot(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reconcileExpiriesLocked(s.nowTime(), "system"); err != nil {
		return err
	}
	state := struct {
		Incidents []*Incident `json:"incidents"`
	}{Incidents: make([]*Incident, 0, len(s.incidents))}
	for _, incident := range s.incidents {
		state.Incidents = append(state.Incidents, cloneIncident(incident))
	}
	sort.Slice(state.Incidents, func(i, j int) bool { return state.Incidents[i].ID < state.Incidents[j].ID })
	return journal.SaveSnapshot(path, state, s.journal.Head())
}

func (s *Store) Verify() (journal.VerifyReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.journal.Verify()
}

func (s *Store) EventsSince(cursor uint64, incidentID string) []journal.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]journal.Event, 0)
	for _, event := range s.events {
		if event.Sequence <= cursor {
			continue
		}
		if incidentID != "" && event.AggregateID != incidentID {
			continue
		}
		result = append(result, event)
	}
	return result
}

func (s *Store) ReconcileExpiries(actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconcileExpiriesLocked(s.nowTime(), actor)
}

func (s *Store) reconcileExpiriesLocked(now time.Time, actor string) error {
	incidentIDs := make([]string, 0, len(s.incidents))
	for id := range s.incidents {
		incidentIDs = append(incidentIDs, id)
	}
	sort.Strings(incidentIDs)
	for _, id := range incidentIDs {
		if err := s.reconcileIncidentExpiriesLocked(id, now, actor); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) reconcileIncidentExpiriesLocked(incidentID string, now time.Time, actor string) error {
	incident, ok := s.incidents[incidentID]
	if !ok {
		return ErrNotFound
	}
	if incident.Status == Closed {
		return nil
	}
	type dueTraffic struct {
		id       string
		sequence uint64
	}
	due := make([]dueTraffic, 0)
	for id, traffic := range incident.Traffic {
		if !IsTerminal(traffic.Status) && !now.Before(traffic.ExpiresAt) {
			due = append(due, dueTraffic{id: id, sequence: traffic.Sequence})
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if due[i].sequence != due[j].sequence {
			return due[i].sequence < due[j].sequence
		}
		return due[i].id < due[j].id
	})
	if actor == "" {
		actor = "system"
	}
	for _, item := range due {
		current := s.incidents[incidentID]
		working := cloneIncident(current)
		traffic := working.Traffic[item.id]
		if IsTerminal(traffic.Status) || now.Before(traffic.ExpiresAt) {
			continue
		}
		if err := expireTraffic(working, &traffic, traffic.ExpiresAt, actor, "expiry boundary"); err != nil && !errors.Is(err, ErrExpired) {
			return err
		}
		working.Traffic[item.id] = traffic
		if _, err := s.commitLocked(working, "traffic.expired", actor, item.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Subscribe(cursor uint64, incidentID string) ([]journal.Event, <-chan journal.Event, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	backlog := make([]journal.Event, 0)
	for _, event := range s.events {
		if event.Sequence > cursor && (incidentID == "" || event.AggregateID == incidentID) {
			backlog = append(backlog, event)
		}
	}
	id := s.nextSub
	s.nextSub++
	ch := make(chan journal.Event, 32)
	s.subscribers[id] = subscriber{incidentID: incidentID, ch: ch}
	cancel := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if existing, ok := s.subscribers[id]; ok {
			close(existing.ch)
			delete(s.subscribers, id)
		}
	}
	return backlog, ch, cancel
}

func CanonicalCallSign(raw string) (string, error) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	value = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
	if len(value) < 3 || len(value) > 16 {
		return "", errors.New("call sign must be 3 to 16 characters")
	}
	for _, r := range value {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '/' && r != '-' {
			return "", errors.New("call sign contains unsupported characters")
		}
	}
	return value, nil
}

func SortTrafficQueue(items []Traffic, now time.Time) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		ra, rb := precedenceRank(a.Precedence), precedenceRank(b.Precedence)
		if ra != rb {
			return ra < rb
		}
		if !a.ExpiresAt.Equal(b.ExpiresAt) {
			return a.ExpiresAt.Before(b.ExpiresAt)
		}
		if !a.ReceivedAt.Equal(b.ReceivedAt) {
			return a.ReceivedAt.Before(b.ReceivedAt)
		}
		return a.Sequence < b.Sequence
	})
}

func QueueGroups(incident *Incident, now time.Time) (actionable, blocked, expired []Traffic) {
	if incident == nil {
		return
	}
	for _, traffic := range incident.Traffic {
		switch {
		case traffic.Status == Expired || (!now.Before(traffic.ExpiresAt) && traffic.Status == Queued):
			expired = append(expired, traffic)
		case traffic.Status == Queued && incident.Status != Open && incident.Status != Reopened:
			blocked = append(blocked, traffic)
		case traffic.Status == Queued:
			actionable = append(actionable, traffic)
		default:
			blocked = append(blocked, traffic)
		}
	}
	SortTrafficQueue(actionable, now)
	SortTrafficQueue(blocked, now)
	sort.Slice(expired, func(i, j int) bool { return expired[i].Sequence < expired[j].Sequence })
	return
}

func IsExpired(traffic Traffic, now time.Time) bool { return !now.Before(traffic.ExpiresAt) }

func normalizePrecedence(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "flash":
		return "flash"
	case "immediate", "immed":
		return "immediate"
	case "priority", "prio":
		return "priority"
	default:
		return "routine"
	}
}

func precedenceRank(value string) int {
	switch normalizePrecedence(value) {
	case "flash":
		return 0
	case "immediate":
		return 1
	case "priority":
		return 2
	default:
		return 3
	}
}

func validateTrafficInput(input TrafficInput) map[string]string {
	fields := map[string]string{}
	if strings.TrimSpace(input.Sender) == "" {
		fields["sender"] = "sender is required"
	}
	if strings.TrimSpace(input.Recipient) == "" {
		fields["recipient"] = "recipient is required"
	}
	if len([]rune(input.Body)) == 0 || len([]rune(input.Body)) > 16000 {
		fields["body"] = "body is required and must be at most 16000 characters"
	}
	if input.IdempotencyKey == "" || len([]rune(input.IdempotencyKey)) > 128 {
		fields["idempotency_key"] = "idempotency key is required and must be at most 128 characters"
	}
	if input.ExpiresAt.IsZero() {
		fields["expires_at"] = "expiry time is required"
	}
	if !input.ReceivedAt.IsZero() && !input.ExpiresAt.IsZero() && !input.ExpiresAt.After(input.ReceivedAt) {
		fields["expires_at"] = "expiry must be after received time"
	}
	if len([]rune(input.HandlingInstructions)) > 4000 {
		fields["handling_instructions"] = "handling instructions are too long"
	}
	return fields
}

func hashTrafficInput(input TrafficInput) string {
	data, _ := json.Marshal(struct {
		Sender, Recipient, Precedence, Body, HandlingInstructions, IdempotencyKey string
		ReceivedAt, ExpiresAt                                                     time.Time
	}{strings.TrimSpace(input.Sender), strings.TrimSpace(input.Recipient), normalizePrecedence(input.Precedence), input.Body, strings.TrimSpace(input.HandlingInstructions), input.IdempotencyKey, input.ReceivedAt.UTC(), input.ExpiresAt.UTC()})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func sameTrafficRequest(traffic Traffic, input TrafficInput) bool {
	if traffic.RequestHash != "" {
		return traffic.RequestHash == hashTrafficInput(input)
	}
	if input.ReceivedAt.IsZero() {
		input.ReceivedAt = traffic.ReceivedAt
	}
	return hashTrafficInput(input) == hashTrafficInput(TrafficInput{Sender: traffic.Sender, Recipient: traffic.Recipient, Precedence: traffic.Precedence, Body: traffic.Body, HandlingInstructions: traffic.HandlingInstructions, ReceivedAt: traffic.ReceivedAt, ExpiresAt: traffic.ExpiresAt, IdempotencyKey: traffic.IdempotencyKey})
}

func validIncidentTransition(from, to IncidentStatus) bool {
	switch from {
	case Planned:
		return to == Open
	case Open:
		return to == Closing
	case Closing:
		return to == Closed || to == Open
	case Closed:
		return to == Reopened
	case Reopened:
		return to == Open || to == Closing
	default:
		return false
	}
}

func validateCloseout(incident *Incident) error {
	missing := make([]string, 0)
	for _, traffic := range incident.Traffic {
		switch traffic.Status {
		case Delivered, Failed, Expired, Cancelled:
		default:
			if strings.TrimSpace(traffic.Disposition) == "" {
				missing = append(missing, fmt.Sprintf("#%d", traffic.Sequence))
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%w: unresolved traffic requires dispositions: %s", ErrConflict, strings.Join(missing, ", "))
	}
	return nil
}

func incidentWritable(status IncidentStatus) bool { return status == Open || status == Reopened }

func statusError(status IncidentStatus) error {
	if status == Closed {
		return ErrClosed
	}
	return fmt.Errorf("%w: incident is %s", ErrConflict, status)
}

func activeTrafficForStation(incident *Incident, stationID string) string {
	for id, traffic := range incident.Traffic {
		if traffic.AssignedStationID == stationID && (traffic.Status == Assigned || traffic.Status == InFlight) {
			return id
		}
	}
	return ""
}

func transitionTraffic(traffic *Traffic, target TrafficStatus, at time.Time, reason, stationID, actor string) {
	from := traffic.Status
	traffic.Status = target
	traffic.History = append(traffic.History, TrafficTransition{At: at, From: from, To: target, Reason: reason, StationID: stationID, Actor: actor})
}

func completeOpenRelayAttempt(traffic *Traffic, at time.Time, outcome, reason string) {
	if len(traffic.RelayAttempts) == 0 {
		return
	}
	last := &traffic.RelayAttempts[len(traffic.RelayAttempts)-1]
	if !last.CompletedAt.IsZero() {
		return
	}
	last.CompletedAt = at
	last.DestinationAcknowledged = false
	last.Outcome = outcome
	last.Reason = reason
}

func expireTraffic(incident *Incident, traffic *Traffic, now time.Time, actor, reason string) error {
	if traffic.Status == Expired {
		return ErrExpired
	}
	if traffic.Status == Delivered || traffic.Status == Failed || traffic.Status == Cancelled {
		return ErrTerminal
	}
	old := traffic.Status
	stationID := traffic.AssignedStationID
	if old == InFlight {
		completeOpenRelayAttempt(traffic, now, "expired", reason)
	}
	traffic.FinalizedAt = now
	traffic.AssignedStationID = ""
	traffic.AssignmentCheckInID = ""
	traffic.AssignedAt = time.Time{}
	traffic.InFlightAt = time.Time{}
	traffic.Reason = reason
	transitionTraffic(traffic, Expired, now, reason, stationID, actor)
	traffic.RecordVersion++
	if station, ok := incident.Stations[stationID]; ok {
		station.Availability = Available
		station.Version++
		incident.Stations[stationID] = station
	}
	incident.Version++
	addAudit(incident, "traffic.expired", now, actor, reason, string(old), string(Expired), traffic.ID)
	return ErrExpired
}

func addAudit(incident *Incident, kind string, at time.Time, actor, details, from, to, recordID string) {
	incident.Audit = append(incident.Audit, AuditEntry{ID: newID("AUD"), Kind: kind, At: at, Actor: actor, Details: details, From: from, To: to, RecordID: recordID})
}

func cleanList(items []string) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func validateRosterStation(input StationInput) map[string]string {
	fields := make(map[string]string)
	if _, err := CanonicalCallSign(input.CallSign); err != nil {
		fields["call_sign"] = err.Error()
	}
	if strings.TrimSpace(input.Operator) == "" {
		fields["operator"] = "operator is required"
	}
	if len([]rune(input.Operator)) > 120 {
		fields["operator"] = "operator is too long"
	}
	if len([]rune(input.Location)) > 160 {
		fields["location"] = "location is too long"
	}
	return fields
}

func rosterValue(row []string, indexes map[string]int, key string) string {
	index, ok := indexes[key]
	if !ok || index < 0 || index >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[index])
}

func splitRosterList(value string) []string {
	value = strings.ReplaceAll(value, "|", ";")
	parts := strings.Split(value, ";")
	if len(parts) == 1 && strings.Contains(value, ",") {
		parts = strings.Split(value, ",")
	}
	return cleanList(parts)
}

func allBlank(row []string) bool {
	for _, value := range row {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return true
}

func newID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

func cloneIncident(incident *Incident) *Incident {
	if incident == nil {
		return nil
	}
	data, _ := json.Marshal(incident)
	var copy Incident
	_ = json.Unmarshal(data, &copy)
	normalizeIncident(&copy)
	return &copy
}

func cloneStation(station *Station) *Station {
	if station == nil {
		return nil
	}
	data, _ := json.Marshal(station)
	var copy Station
	_ = json.Unmarshal(data, &copy)
	return &copy
}

func cloneTraffic(traffic *Traffic) *Traffic {
	if traffic == nil {
		return nil
	}
	data, _ := json.Marshal(traffic)
	var copy Traffic
	_ = json.Unmarshal(data, &copy)
	if copy.Acknowledgements == nil {
		copy.Acknowledgements = make(map[string]bool)
	}
	return &copy
}

func normalizeIncident(incident *Incident) {
	if incident.Stations == nil {
		incident.Stations = make(map[string]Station)
	}
	if incident.Traffic == nil {
		incident.Traffic = make(map[string]Traffic)
	}
	if incident.Idempotency == nil {
		incident.Idempotency = make(map[string]string)
	}
	if incident.NextTrafficSequence == 0 {
		max := uint64(0)
		for _, traffic := range incident.Traffic {
			if traffic.Sequence > max {
				max = traffic.Sequence
			}
		}
		incident.NextTrafficSequence = max + 1
	}
	for id, traffic := range incident.Traffic {
		if traffic.Acknowledgements == nil {
			traffic.Acknowledgements = make(map[string]bool)
		}
		incident.Traffic[id] = traffic
	}
}

func (s *Store) LoadSnapshot(path string) error {
	// Journal replay remains authoritative. This method intentionally validates
	// the snapshot and returns a diagnostic without replacing live state.
	_, err := journal.LoadSnapshot(path)
	return err
}

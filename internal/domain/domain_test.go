package domain

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCanonicalCallSignAndQueueOrdering(t *testing.T) {
	canonical, err := CanonicalCallSign(" k1 abc ")
	if err != nil || canonical != "K1ABC" {
		t.Fatalf("canonical = %q, err = %v", canonical, err)
	}
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	items := []Traffic{
		{Sequence: 3, Precedence: "routine", ReceivedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
		{Sequence: 2, Precedence: "flash", ReceivedAt: now.Add(-3 * time.Minute), ExpiresAt: now.Add(3 * time.Hour)},
		{Sequence: 1, Precedence: "priority", ReceivedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(2 * time.Hour)},
	}
	SortTrafficQueue(items, now)
	if items[0].Sequence != 2 || items[1].Sequence != 1 || items[2].Sequence != 3 {
		t.Fatalf("unexpected queue order: %#v", items)
	}
	if !IsExpired(Traffic{ExpiresAt: now}, now) {
		t.Fatal("expiry boundary should be inclusive")
	}
}

func TestConcurrentClaimsAndStationReassignment(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	incident, err := store.CreateIncident(IncidentInput{Title: "Claim test", Timezone: "UTC", Frequency: "146.520", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	incident, err = store.TransitionIncident(incident.ID, Open, "open", "test")
	if err != nil {
		t.Fatal(err)
	}
	station, err := store.CheckInStation(incident.ID, StationInput{CallSign: "K1ABC", Operator: "Ada", Location: "north"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	traffic, _, err := store.SubmitTraffic(incident.ID, TrafficInput{Sender: "K1ABC", Recipient: "N0CTL", Precedence: "priority", Body: "status report", ReceivedAt: time.Now(), ExpiresAt: expires, IdempotencyKey: "claim-1"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.ClaimTraffic(incident.ID, traffic.ID, station.ID, traffic.RecordVersion, "operator")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatalf("unexpected claim error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected one successful claim, got %d", successes)
	}
	updated, err := store.GetIncident(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimed := updated.Traffic[traffic.ID]
	currentStation := updated.Stations[station.ID]
	if _, err := store.UpdateStationAvailability(incident.ID, station.ID, TemporarilyAway, currentStation.Version, "operator"); !errors.Is(err, ErrBusy) {
		t.Fatalf("expected station busy error, got %v", err)
	}
	if _, err := store.ReleaseTraffic(incident.ID, traffic.ID, claimed.RecordVersion, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateStationAvailability(incident.ID, station.ID, CheckedOut, 0, "operator"); err != nil {
		t.Fatal(err)
	}
}

func TestIdempotentSubmissionReplayAndCloseout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	incident, err := store.CreateIncident(IncidentInput{Title: "Replay test", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	incident, err = store.TransitionIncident(incident.ID, Open, "open", "test")
	if err != nil {
		t.Fatal(err)
	}
	received := time.Now().UTC()
	input := TrafficInput{Sender: "K1ABC", Recipient: "N0CTL", Precedence: "routine", Body: "repeatable", ReceivedAt: received, ExpiresAt: received.Add(time.Hour), IdempotencyKey: "same-key"}
	first, existing, err := store.SubmitTraffic(incident.ID, input, "test")
	if err != nil || existing {
		t.Fatalf("first submit = %#v, existing=%v, err=%v", first, existing, err)
	}
	second, existing, err := store.SubmitTraffic(incident.ID, input, "test")
	if err != nil || !existing || first.ID != second.ID {
		t.Fatalf("retry = %#v, existing=%v, err=%v", second, existing, err)
	}
	second.History[0].Actor = "mutated caller"
	second.Acknowledgements["external"] = true
	unchanged, err := store.GetIncident(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Traffic[first.ID].History[0].Actor == "mutated caller" || unchanged.Traffic[first.ID].Acknowledgements["external"] {
		t.Fatal("idempotent return aliased store-owned traffic")
	}
	if _, err := store.TransitionIncident(incident.ID, Closing, "wind down", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Closeout(incident.ID, "test"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected unresolved closeout conflict, got %v", err)
	}
	if _, err := store.SetDisposition(incident.ID, first.ID, "deferred to next net", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Closeout(incident.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, err := reopened.GetIncident(incident.ID)
	if err != nil || loaded.Status != Closed || loaded.Traffic[first.ID].Disposition == "" {
		t.Fatalf("replayed state = %#v, err=%v", loaded, err)
	}
}

func TestRosterPreviewRejectsRowsWithoutLosingValidRows(t *testing.T) {
	preview, err := PreviewRosterCSV([]byte("call_sign,operator,location,bands\nK1ABC,Ada,North,2m;70cm\nBAD!,,South,2m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if preview.ValidRows != 1 || preview.InvalidRows != 1 || len(preview.Rows) != 2 {
		t.Fatalf("preview = %#v", preview)
	}
	if preview.Rows[0].CanonicalCallSign != "K1ABC" || len(preview.Rows[1].Errors) == 0 {
		t.Fatalf("row validation = %#v", preview.Rows)
	}
}

func TestZeroReceivedTimeIsIdempotent(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	incident, err := store.CreateIncident(IncidentInput{Title: "Idempotency", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	incident, err = store.TransitionIncident(incident.ID, Open, "ready", "test")
	if err != nil {
		t.Fatal(err)
	}
	input := TrafficInput{Sender: "K1ABC", Recipient: "N0CTL", Body: "same", ExpiresAt: time.Now().Add(time.Hour), IdempotencyKey: "zero-received"}
	first, existing, err := store.SubmitTraffic(incident.ID, input, "test")
	if err != nil || existing {
		t.Fatalf("first submit existing=%v err=%v", existing, err)
	}
	second, existing, err := store.SubmitTraffic(incident.ID, input, "test")
	if err != nil || !existing || first.ID != second.ID {
		t.Fatalf("retry traffic=%#v existing=%v err=%v", second, existing, err)
	}
}

func TestExpiryAndClosedGuards(t *testing.T) {
	clock := time.Now().UTC()
	store, err := NewStoreWithClock(filepath.Join(t.TempDir(), "journal.jsonl"), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	incident, err := store.CreateIncident(IncidentInput{Title: "Guards", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	incident, err = store.TransitionIncident(incident.ID, Open, "ready", "test")
	if err != nil {
		t.Fatal(err)
	}
	station, err := store.CheckInStation(incident.ID, StationInput{CallSign: "K1ABC", Operator: "Ada"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	traffic, _, err := store.SubmitTraffic(incident.ID, TrafficInput{Sender: "K1ABC", Recipient: "N0CTL", Body: "expires", ReceivedAt: clock, ExpiresAt: clock.Add(time.Hour), IdempotencyKey: "expiry-guard"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimTraffic(incident.ID, traffic.ID, station.ID, traffic.RecordVersion, "test")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	if _, err := store.StartTraffic(incident.ID, traffic.ID, claimed.RecordVersion, "test"); !errors.Is(err, ErrExpired) {
		t.Fatalf("start after expiry = %v", err)
	}
	loaded, _ := store.GetIncident(incident.ID)
	if loaded.Traffic[traffic.ID].Status != Expired {
		t.Fatalf("traffic after expiry = %s", loaded.Traffic[traffic.ID].Status)
	}
	if _, err := store.SetDisposition(incident.ID, traffic.ID, "expired during net", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionIncident(incident.ID, Closing, "wind down", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Closeout(incident.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CancelTraffic(incident.ID, traffic.ID, "late retry", 0, "test"); !errors.Is(err, ErrClosed) {
		t.Fatalf("cancel closed traffic = %v", err)
	}
}

func TestSnapshotAnchoredReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.jsonl")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	incident, err := store.CreateIncident(IncidentInput{Title: "Snapshot", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSnapshot(filepath.Join(dir, "snapshot.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionIncident(incident.ID, Open, "suffix event", "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, err := reopened.GetIncident(incident.ID)
	if err != nil || loaded.Status != Open {
		t.Fatalf("snapshot replay = %#v err=%v", loaded, err)
	}
	if len(reopened.EventsSince(0, incident.ID)) != 2 {
		t.Fatalf("event history lost across snapshot: %d", len(reopened.EventsSince(0, incident.ID)))
	}
}

func TestNaturalExpiryPersistsBeforeSummaryAndReplay(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	store, err := NewStoreWithClock(path, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	incident, err := store.CreateIncident(IncidentInput{Title: "Expiry replay", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	incident, err = store.TransitionIncident(incident.ID, Open, "ready", "test")
	if err != nil {
		t.Fatal(err)
	}
	traffic, _, err := store.SubmitTraffic(incident.ID, TrafficInput{Sender: "K1ABC", Recipient: "N0CTL", Body: "boundary", ReceivedAt: clock, ExpiresAt: clock.Add(time.Hour), IdempotencyKey: "natural-expiry"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	eventsBefore := len(store.EventsSince(0, incident.ID))
	clock = traffic.ExpiresAt.Add(3 * time.Hour)

	summary, err := store.Summary(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ExpiredCount != 1 || summary.UnresolvedCount != 0 {
		t.Fatalf("summary after boundary = %#v", summary)
	}
	loaded, err := store.GetIncident(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	expired := loaded.Traffic[traffic.ID]
	if expired.Status != Expired || expired.RecordVersion != traffic.RecordVersion+1 {
		t.Fatalf("persisted traffic = %#v", expired)
	}
	if !expired.FinalizedAt.Equal(traffic.ExpiresAt) || !expired.History[len(expired.History)-1].At.Equal(traffic.ExpiresAt) {
		t.Fatalf("expiry recorded at observation time instead of boundary: %#v", expired)
	}
	if len(expired.History) != 2 || len(loaded.Audit) == 0 || loaded.Audit[len(loaded.Audit)-1].Kind != "traffic.expired" {
		t.Fatalf("expiry history/audit not recorded: traffic=%#v audit=%#v", expired.History, loaded.Audit)
	}
	if got := len(store.EventsSince(0, incident.ID)); got != eventsBefore+1 {
		t.Fatalf("expiry events = %d, want %d", got, eventsBefore+1)
	}
	if _, err := store.Summary(incident.ID); err != nil {
		t.Fatal(err)
	}
	if got := len(store.EventsSince(0, incident.ID)); got != eventsBefore+1 {
		t.Fatalf("repeated reconciliation appended another event: %d", got)
	}

	if _, err := store.TransitionIncident(incident.ID, Closing, "wind down", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Closeout(incident.ID, "test"); err != nil {
		t.Fatalf("natural expiry should not require a disposition: %v", err)
	}
	archiveJSON, err := store.Export(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	var archive Archive
	if err := json.Unmarshal(archiveJSON, &archive); err != nil {
		t.Fatal(err)
	}
	if archive.Incident.Traffic[traffic.ID].Status != Expired {
		t.Fatalf("archive traffic = %#v", archive.Incident.Traffic[traffic.ID])
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	replayed, err := NewStoreWithClock(path, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	recovered, err := replayed.GetIncident(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != Closed || recovered.Traffic[traffic.ID].Status != Expired {
		t.Fatalf("replayed incident = %#v", recovered)
	}
}

func TestFailedRelayAttemptKeepsTrafficActiveAndReplayable(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	store, err := NewStoreWithClock(path, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	incident, err := store.CreateIncident(IncidentInput{Title: "Relay retry", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	incident, err = store.TransitionIncident(incident.ID, Open, "ready", "test")
	if err != nil {
		t.Fatal(err)
	}
	station, err := store.CheckInStation(incident.ID, StationInput{CallSign: "K1ABC", Operator: "Ada"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	traffic, _, err := store.SubmitTraffic(incident.ID, TrafficInput{Sender: "K1ABC", Recipient: "N0CTL", Body: "retry relay", ReceivedAt: clock, ExpiresAt: clock.Add(4 * time.Hour), IdempotencyKey: "relay-retry"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimTraffic(incident.ID, traffic.ID, station.ID, traffic.RecordVersion, "test")
	if err != nil {
		t.Fatal(err)
	}
	inFlight, err := store.StartTraffic(incident.ID, traffic.ID, claimed.RecordVersion, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FailRelayAttempt(incident.ID, traffic.ID, "", inFlight.RecordVersion, "test"); err == nil {
		t.Fatal("empty relay failure reason should be rejected")
	}
	clock = clock.Add(5 * time.Minute)
	failedLeg, err := store.FailRelayAttempt(incident.ID, traffic.ID, "no destination response", inFlight.RecordVersion, "test")
	if err != nil {
		t.Fatal(err)
	}
	if failedLeg.Status != Assigned || failedLeg.AssignedStationID != station.ID || len(failedLeg.RelayAttempts) != 1 {
		t.Fatalf("traffic after failed leg = %#v", failedLeg)
	}
	attempt := failedLeg.RelayAttempts[0]
	if attempt.CompletedAt.IsZero() || attempt.Outcome != "failed" || attempt.DestinationAcknowledged || attempt.Reason != "no destination response" {
		t.Fatalf("failed relay attempt = %#v", attempt)
	}
	loaded, err := store.GetIncident(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Stations[station.ID].Availability != StationAssigned {
		t.Fatalf("station availability = %s", loaded.Stations[station.ID].Availability)
	}
	if _, err := store.FailRelayAttempt(incident.ID, traffic.ID, "stale retry", inFlight.RecordVersion, "test"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale relay failure = %v", err)
	}
	clock = clock.Add(time.Minute)
	if _, err := store.StartTraffic(incident.ID, traffic.ID, 0, "test"); err == nil {
		t.Fatal("retry without an expected version should be rejected")
	}
	retried, err := store.StartTraffic(incident.ID, traffic.ID, failedLeg.RecordVersion, "test")
	if err != nil {
		t.Fatal(err)
	}
	if retried.Status != InFlight || len(retried.RelayAttempts) != 2 || retried.RelayAttempts[1].Number != 2 {
		t.Fatalf("retried traffic = %#v", retried)
	}
	clock = traffic.ExpiresAt.Add(time.Minute)
	if _, err := store.Summary(incident.ID); err != nil {
		t.Fatal(err)
	}
	expiredIncident, err := store.GetIncident(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	expiredTraffic := expiredIncident.Traffic[traffic.ID]
	if expiredTraffic.Status != Expired || expiredTraffic.RelayAttempts[1].Outcome != "expired" || expiredTraffic.RelayAttempts[1].CompletedAt.IsZero() {
		t.Fatalf("in-flight expiry left relay open: %#v", expiredTraffic)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	replayed, err := NewStoreWithClock(path, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	recovered, err := replayed.GetIncident(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Traffic[traffic.ID].RelayAttempts[0].Outcome != "failed" || recovered.Traffic[traffic.ID].RelayAttempts[1].Outcome != "expired" || len(recovered.Traffic[traffic.ID].RelayAttempts) != 2 {
		t.Fatalf("replayed relay attempts = %#v", recovered.Traffic[traffic.ID].RelayAttempts)
	}
}

func TestClosedIncidentDoesNotChangeWhenTrafficLaterExpires(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store, err := NewStoreWithClock(filepath.Join(t.TempDir(), "journal.jsonl"), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	incident, err := store.CreateIncident(IncidentInput{Title: "Frozen closeout", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	incident, err = store.TransitionIncident(incident.ID, Open, "ready", "test")
	if err != nil {
		t.Fatal(err)
	}
	traffic, _, err := store.SubmitTraffic(incident.ID, TrafficInput{Sender: "K1ABC", Recipient: "N0CTL", Body: "deferred", ReceivedAt: clock, ExpiresAt: clock.Add(time.Hour), IdempotencyKey: "frozen-closeout"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetDisposition(incident.ID, traffic.ID, "carry to next operational period", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionIncident(incident.ID, Closing, "wind down", "test"); err != nil {
		t.Fatal(err)
	}
	closed, err := store.Closeout(incident.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	events := len(store.EventsSince(0, incident.ID))
	clock = clock.Add(2 * time.Hour)
	loaded, err := store.GetIncident(incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != closed.Version || loaded.Traffic[traffic.ID].Status != Queued || len(store.EventsSince(0, incident.ID)) != events {
		t.Fatalf("closed incident changed after time passage: %#v", loaded)
	}
}

func TestExplicitExpiryUsesExpiryBoundaryTimestamp(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store, err := NewStoreWithClock(filepath.Join(t.TempDir(), "journal.jsonl"), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	incident, err := store.CreateIncident(IncidentInput{Title: "Explicit expiry", Timezone: "UTC", Frequency: "146.52", ControlOperator: "N0CTL"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	incident, err = store.TransitionIncident(incident.ID, Open, "ready", "test")
	if err != nil {
		t.Fatal(err)
	}
	traffic, _, err := store.SubmitTraffic(incident.ID, TrafficInput{Sender: "K1ABC", Recipient: "N0CTL", Body: "expires", ReceivedAt: clock, ExpiresAt: clock.Add(time.Hour), IdempotencyKey: "explicit-expiry"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(4 * time.Hour)
	expired, err := store.ExpireTraffic(incident.ID, traffic.ID, traffic.RecordVersion, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !expired.FinalizedAt.Equal(traffic.ExpiresAt) || !expired.History[len(expired.History)-1].At.Equal(traffic.ExpiresAt) {
		t.Fatalf("explicit expiry timestamps = %#v", expired)
	}
}

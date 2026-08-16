package journal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestChecksummedReplayAndIncompleteTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, err := Open(path, Options{Durable: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append("incident.created", json.RawMessage(`{"id":"one"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append("incident.opened", json.RawMessage(`{"id":"one"}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"v":1,"seq":3`); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()

	j, err = Open(path, Options{Durable: true})
	if err != nil {
		t.Fatal(err)
	}
	if j.Tail().State != TailIncomplete {
		t.Fatalf("tail = %#v", j.Tail())
	}
	if _, err := j.Append("should.fail", json.RawMessage(`{}`)); !errors.Is(err, ErrNeedsRepair) {
		t.Fatalf("append with incomplete tail = %v", err)
	}
	if err := j.RepairTail(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append("incident.closed", json.RawMessage(`{"id":"one"}`)); err != nil {
		t.Fatal(err)
	}
	report, err := j.Verify()
	if err != nil || report.Head.Sequence != 3 || report.Tail.State != TailClean {
		t.Fatalf("verify = %#v, err=%v", report, err)
	}
	_ = j.Close()
}

func TestCommittedCorruptionIsNotIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	if err := os.WriteFile(path, []byte(`{"v":1,"seq":1,"kind":"x","timestamp":"now","payload":{},"prev_checksum":"","checksum":"bad"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt journal error = %v", err)
	}
}

func TestJournalRejectsSecondWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	first, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := Open(path, Options{}); err == nil {
		t.Fatal("second writer unexpectedly acquired journal")
	}
}

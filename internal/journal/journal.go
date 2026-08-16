package journal

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var (
	ErrCorrupt       = errors.New("journal: corrupt committed record")
	ErrNeedsRepair   = errors.New("journal: incomplete trailing record requires repair")
	ErrCommitUnknown = errors.New("journal: append commit status unknown")
	ErrClosed        = errors.New("journal: closed")
)

type Options struct {
	Durable        bool
	MaxRecordBytes int64
}

type Head struct {
	Sequence uint64 `json:"sequence"`
	Checksum string `json:"checksum"`
}

type Event struct {
	Version          int             `json:"v"`
	Sequence         uint64          `json:"seq"`
	Kind             string          `json:"kind"`
	AggregateID      string          `json:"-"`
	AggregateVersion uint64          `json:"-"`
	Timestamp        string          `json:"timestamp"`
	Payload          json.RawMessage `json:"payload"`
	PrevChecksum     string          `json:"prev_checksum"`
	Checksum         string          `json:"checksum"`
}

type TailState string

const (
	TailClean      TailState = "clean"
	TailIncomplete TailState = "incomplete"
)

type TailInfo struct {
	State  TailState `json:"state"`
	Offset int64     `json:"offset"`
}

type VerifyReport struct {
	Head    Head     `json:"head"`
	Records uint64   `json:"records"`
	Tail    TailInfo `json:"tail"`
}

type Journal struct {
	mu      sync.Mutex
	file    *os.File
	lock    *os.File
	path    string
	options Options
	head    Head
	tail    TailInfo
	tainted bool
	closed  bool
}

func Open(path string, options Options) (*Journal, error) {
	if stringsTrim(path) == "" {
		return nil, errors.New("journal path is required")
	}
	if options.MaxRecordBytes <= 0 {
		options.MaxRecordBytes = 4 << 20
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		_ = file.Close()
		return nil, fmt.Errorf("journal is already open: %w", err)
	}
	j := &Journal{file: file, lock: lock, path: path, options: options, tail: TailInfo{State: TailClean}}
	if err := j.scanLocked(nil); err != nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
		_ = file.Close()
		return nil, err
	}
	return j, nil
}

func (j *Journal) Append(kind string, payload json.RawMessage) (Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return Event{}, ErrClosed
	}
	if j.tainted {
		return Event{}, ErrCommitUnknown
	}
	if j.tail.State == TailIncomplete {
		return Event{}, ErrNeedsRepair
	}
	if kind == "" {
		return Event{}, errors.New("journal event kind is required")
	}
	if len(payload) > int(j.options.MaxRecordBytes) {
		return Event{}, fmt.Errorf("journal payload exceeds %d bytes", j.options.MaxRecordBytes)
	}
	sequence := j.head.Sequence + 1
	if sequence == 0 {
		return Event{}, errors.New("journal sequence overflow")
	}
	event := Event{
		Version:      1,
		Sequence:     sequence,
		Kind:         kind,
		Timestamp:    timestampNow(),
		Payload:      append(json.RawMessage(nil), payload...),
		PrevChecksum: j.head.Checksum,
	}
	event.Checksum = checksum(event)
	line, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	line = append(line, '\n')
	if int64(len(line)) > j.options.MaxRecordBytes {
		return Event{}, fmt.Errorf("journal record exceeds %d bytes", j.options.MaxRecordBytes)
	}
	n, err := j.file.Write(line)
	if err != nil || n != len(line) {
		j.tainted = true
		if err == nil {
			err = io.ErrShortWrite
		}
		return Event{}, fmt.Errorf("%w: %v", ErrCommitUnknown, err)
	}
	if j.options.Durable {
		if err := j.file.Sync(); err != nil {
			j.tainted = true
			return Event{}, fmt.Errorf("%w: %v", ErrCommitUnknown, err)
		}
	}
	j.head = Head{Sequence: event.Sequence, Checksum: event.Checksum}
	return event, nil
}

func (j *Journal) ForEach(fn func(Event) error) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	return j.scanLocked(fn)
}

func (j *Journal) Verify() (VerifyReport, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return VerifyReport{}, ErrClosed
	}
	if err := j.scanLocked(nil); err != nil {
		return VerifyReport{}, err
	}
	return VerifyReport{Head: j.head, Records: j.head.Sequence, Tail: j.tail}, nil
}

func (j *Journal) Head() Head {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.head
}

func (j *Journal) Tail() TailInfo {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.tail
}

func (j *Journal) RepairTail() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	if j.tail.State != TailIncomplete {
		return nil
	}
	if err := j.file.Truncate(j.tail.Offset); err != nil {
		return err
	}
	if j.options.Durable {
		if err := j.file.Sync(); err != nil {
			return err
		}
	}
	if _, err := j.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	j.tail = TailInfo{State: TailClean}
	j.tainted = false
	return nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	fileErr := j.file.Close()
	if j.lock != nil {
		_ = syscall.Flock(int(j.lock.Fd()), syscall.LOCK_UN)
		if err := j.lock.Close(); fileErr == nil {
			fileErr = err
		}
	}
	return fileErr
}

func (j *Journal) scanLocked(fn func(Event) error) error {
	if _, err := j.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(j.file, 64*1024)
	var offset int64
	var head Head
	tail := TailInfo{State: TailClean}
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if int64(len(line)) > j.options.MaxRecordBytes {
				return fmt.Errorf("%w: record at offset %d exceeds limit", ErrCorrupt, offset)
			}
			if err == io.EOF {
				tail = TailInfo{State: TailIncomplete, Offset: offset}
				break
			}
			if err != nil {
				return err
			}
			line = line[:len(line)-1]
			var event Event
			if err := json.Unmarshal(line, &event); err != nil {
				return fmt.Errorf("%w at offset %d: %v", ErrCorrupt, offset, err)
			}
			if err := validate(event, head); err != nil {
				return fmt.Errorf("%w at offset %d: %v", ErrCorrupt, offset, err)
			}
			if fn != nil {
				if err := fn(event); err != nil {
					return err
				}
			}
			head = Head{Sequence: event.Sequence, Checksum: event.Checksum}
			offset += int64(len(line)) + 1
			continue
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if _, err := j.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	j.head = head
	j.tail = tail
	return nil
}

func validate(event Event, previous Head) error {
	if event.Version != 1 {
		return fmt.Errorf("unsupported version %d", event.Version)
	}
	if event.Sequence != previous.Sequence+1 {
		return fmt.Errorf("sequence %d after %d", event.Sequence, previous.Sequence)
	}
	if event.PrevChecksum != previous.Checksum {
		return errors.New("previous checksum mismatch")
	}
	if event.Kind == "" {
		return errors.New("missing kind")
	}
	if event.Checksum == "" || event.Checksum != checksum(event) {
		return errors.New("checksum mismatch")
	}
	return nil
}

func checksum(event Event) string {
	body := struct {
		Version      int             `json:"v"`
		Sequence     uint64          `json:"seq"`
		Kind         string          `json:"kind"`
		Timestamp    string          `json:"timestamp"`
		Payload      json.RawMessage `json:"payload"`
		PrevChecksum string          `json:"prev_checksum"`
	}{event.Version, event.Sequence, event.Kind, event.Timestamp, event.Payload, event.PrevChecksum}
	data, _ := json.Marshal(body)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func timestampNow() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func stringsTrim(value string) string {
	for len(value) > 0 && (value[0] == ' ' || value[0] == '\t' || value[0] == '\n' || value[0] == '\r') {
		value = value[1:]
	}
	for len(value) > 0 && (value[len(value)-1] == ' ' || value[len(value)-1] == '\t' || value[len(value)-1] == '\n' || value[len(value)-1] == '\r') {
		value = value[:len(value)-1]
	}
	return value
}

type Snapshot struct {
	Version  uint8           `json:"version"`
	Head     Head            `json:"head"`
	State    json.RawMessage `json:"state"`
	Checksum string          `json:"checksum"`
}

func SaveSnapshot(path string, state any, head Head) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	snapshot := Snapshot{Version: 1, Head: head, State: data}
	snapshot.Checksum = snapshotChecksum(snapshot)
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".netweave-snapshot-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

func LoadSnapshot(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Version != 1 || snapshot.Checksum == "" || snapshot.Checksum != snapshotChecksum(snapshot) {
		return Snapshot{}, errors.New("invalid snapshot checksum")
	}
	return snapshot, nil
}

func snapshotChecksum(snapshot Snapshot) string {
	body := struct {
		Version uint8           `json:"version"`
		Head    Head            `json:"head"`
		State   json.RawMessage `json:"state"`
	}{snapshot.Version, snapshot.Head, snapshot.State}
	data, _ := json.Marshal(body)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

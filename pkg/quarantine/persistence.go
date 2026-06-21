package quarantine

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

const LogMagicNumber uint16 = 0x564D // VM

const (
	ErrPersistenceCorruptionPrefix = "PERSISTENCE_CORRUPTION"
	ErrSecurityAlertPrefix         = "SECURITY_ALERT"
)

type FileLedger struct {
	mu   sync.Mutex
	file *os.File
	path string
}

func NewFileLedger(path string) (*FileLedger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	return &FileLedger{file: f, path: path}, nil
}

func (l *FileLedger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// AppendEvent serializes a RevocationEvent and commits it to durable storage.
// Record layout: length uint32 | magic uint16 | JSON payload | SHA-256(length+magic+payload)
func (l *FileLedger) AppendEvent(event RevocationEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return errors.New("PERSISTENCE_CLOSED: file ledger is closed")
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if len(payload) == 0 {
		return errors.New("INVALID_LEDGER_EVENT: empty payload")
	}
	if len(payload) > int(^uint32(0)) {
		return errors.New("INVALID_LEDGER_EVENT: payload exceeds uint32 length")
	}

	length := uint32(len(payload))
	checksum := recordChecksum(length, LogMagicNumber, payload)

	if err := binary.Write(l.file, binary.BigEndian, length); err != nil {
		return err
	}
	if err := binary.Write(l.file, binary.BigEndian, LogMagicNumber); err != nil {
		return err
	}
	if _, err := l.file.Write(payload); err != nil {
		return err
	}
	if _, err := l.file.Write(checksum[:]); err != nil {
		return err
	}

	return l.file.Sync()
}

// ReplayGenesis reads the durable ledger from byte zero and reconstructs the event stream.
func (l *FileLedger) ReplayGenesis() ([]RevocationEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return nil, errors.New("PERSISTENCE_CLOSED: file ledger is closed")
	}

	return replayFrom(l.file)
}

// ReplayFile replays a ledger path without requiring an existing FileLedger instance.
func ReplayFile(path string) ([]RevocationEvent, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return replayFrom(f)
}

// RecoverMonitorFromFile replays a durable ledger and publishes the reconstructed runtime snapshot.
func RecoverMonitorFromFile(path string, version uint64) (*RuntimeMonitor, *RuntimeSnapshot, error) {
	events, err := ReplayFile(path)
	if err != nil {
		return nil, nil, err
	}
	monitor := NewRuntimeMonitor()
	for _, event := range events {
		monitor.AppendEvent(event)
	}
	snap := CompileSnapshot(events, version, NowUTC())
	monitor.SwapActiveSnapshot(snap)
	return monitor, snap, nil
}

func replayFrom(f *os.File) ([]RevocationEvent, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var events []RevocationEvent

	for {
		var length uint32
		err := binary.Read(f, binary.BigEndian, &length)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: failed reading record length: %w", ErrPersistenceCorruptionPrefix, err)
		}
		if length == 0 {
			return nil, errors.New(ErrPersistenceCorruptionPrefix + ": zero-length log packet")
		}

		var magic uint16
		if err := binary.Read(f, binary.BigEndian, &magic); err != nil {
			return nil, errors.New(ErrPersistenceCorruptionPrefix + ": missing log packet boundary magic")
		}
		if magic != LogMagicNumber {
			return nil, errors.New(ErrPersistenceCorruptionPrefix + ": invalid log packet initialization signature")
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(f, payload); err != nil {
			return nil, errors.New(ErrPersistenceCorruptionPrefix + ": truncated or partial write encountered mid-stream")
		}

		var checksum [32]byte
		if _, err := io.ReadFull(f, checksum[:]); err != nil {
			return nil, errors.New(ErrPersistenceCorruptionPrefix + ": truncated validation signature segment")
		}

		expected := recordChecksum(length, LogMagicNumber, payload)
		if expected != checksum {
			return nil, errors.New(ErrSecurityAlertPrefix + ": cryptographic record tampering detected during log parsing")
		}

		var event RevocationEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, nil
}

func recordChecksum(length uint32, magic uint16, payload []byte) [32]byte {
	h := sha256.New()
	var lenBuf [4]byte
	var magicBuf [2]byte
	binary.BigEndian.PutUint32(lenBuf[:], length)
	binary.BigEndian.PutUint16(magicBuf[:], magic)
	h.Write(lenBuf[:])
	h.Write(magicBuf[:])
	h.Write(payload)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

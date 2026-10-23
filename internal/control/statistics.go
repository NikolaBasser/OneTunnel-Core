package control

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionStatistics describes one successful transport attempt. Nil counters
// mean the connected engine does not expose them; zero is a measured value.
type ConnectionStatistics struct {
	SchemaVersion          int     `json:"SchemaVersion"`
	SessionID              string  `json:"SessionID"`
	ElapsedMilliseconds    uint64  `json:"ElapsedMilliseconds"`
	UploadedBytes          *uint64 `json:"UploadedBytes"`
	DownloadedBytes        *uint64 `json:"DownloadedBytes"`
	UploadBytesPerSecond   *uint64 `json:"UploadBytesPerSecond"`
	DownloadBytesPerSecond *uint64 `json:"DownloadBytesPerSecond"`
	Scope                  string  `json:"Scope"`
}

// StatisticsAccumulator is shared by tracker callbacks and serialized runtime
// sampling. Counter methods are atomic-only and safe from packet callbacks.
type StatisticsAccumulator struct {
	started                              time.Time
	scope                                string
	uploaded, downloaded                 atomic.Uint64
	sampleMu                             sync.Mutex
	previousAt                           time.Time
	previousSet                          bool
	previousUploaded, previousDownloaded uint64
	rateReady                            bool
	uploadRate, downloadRate             *uint64
	nativeReady                          bool
	nativeUploaded, nativeDownloaded     uint64
}

func NewStatisticsAccumulator(started time.Time, scope string) (*StatisticsAccumulator, string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, "", err
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	text := hex.EncodeToString(id[:])
	session := text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
	if scope != "proxy-payload" && scope != "proxy-payload-and-packets" && scope != "native-transport" {
		return nil, "", ErrStatisticsScope
	}
	return &StatisticsAccumulator{started: started, scope: scope}, session, nil
}

var ErrStatisticsScope = errors.New("invalid statistics scope")

func addSaturating(counter *atomic.Uint64, n uint64) {
	for {
		old := counter.Load()
		if n > math.MaxUint64-old {
			n = math.MaxUint64 - old
		}
		if counter.CompareAndSwap(old, old+n) {
			return
		}
	}
}

func (s *StatisticsAccumulator) AddUploaded(n uint64) {
	if s != nil {
		addSaturating(&s.uploaded, n)
	}
}
func (s *StatisticsAccumulator) AddDownloaded(n uint64) {
	if s != nil {
		addSaturating(&s.downloaded, n)
	}
}

// MarkStarted sets the successful transport start after engine initialization.
func (s *StatisticsAccumulator) MarkStarted(started time.Time) {
	if s == nil {
		return
	}
	s.sampleMu.Lock()
	s.started = started
	s.previousAt = time.Time{}
	s.previousSet = false
	s.rateReady = false
	s.uploadRate, s.downloadRate = nil, nil
	s.sampleMu.Unlock()
}

// ResetRateBaseline marks a sampling gap so the next rate waits for two fresh
// successful samples while retaining cumulative byte totals.
func (s *StatisticsAccumulator) ResetRateBaseline() {
	if s == nil {
		return
	}
	s.sampleMu.Lock()
	s.previousSet = false
	s.rateReady = false
	s.uploadRate, s.downloadRate = nil, nil
	s.sampleMu.Unlock()
}

// UpdateAbsolute folds native monotonic counters into this session. A regression
// establishes a new baseline without subtracting or wrapping the accumulated total.
func (s *StatisticsAccumulator) UpdateAbsolute(uploaded, downloaded uint64) {
	if s == nil {
		return
	}
	s.sampleMu.Lock()
	defer s.sampleMu.Unlock()
	if !s.nativeReady {
		s.nativeUploaded, s.nativeDownloaded, s.nativeReady = uploaded, downloaded, true
		addSaturating(&s.uploaded, uploaded)
		addSaturating(&s.downloaded, downloaded)
		return
	}
	if uploaded >= s.nativeUploaded {
		addSaturating(&s.uploaded, uploaded-s.nativeUploaded)
	}
	if downloaded >= s.nativeDownloaded {
		addSaturating(&s.downloaded, downloaded-s.nativeDownloaded)
	}
	s.nativeUploaded, s.nativeDownloaded = uploaded, downloaded
}

func rate(delta uint64, elapsed time.Duration) uint64 {
	if elapsed <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(delta, uint64(time.Second))
	if hi >= uint64(elapsed) {
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, uint64(elapsed))
	return q
}

func ptr(v uint64) *uint64 { return &v }

// Snapshot returns a detached, immutable view and advances the rate baseline.
func (s *StatisticsAccumulator) Snapshot(now time.Time, sessionID string) *ConnectionStatistics {
	if s == nil {
		return nil
	}
	s.sampleMu.Lock()
	defer s.sampleMu.Unlock()
	uploaded, downloaded := s.uploaded.Load(), s.downloaded.Load()
	elapsed := now.Sub(s.started)
	if elapsed < 0 {
		elapsed = 0
	}
	ms := uint64(elapsed / time.Millisecond)
	if s.previousSet && now.After(s.previousAt) && uploaded >= s.previousUploaded && downloaded >= s.previousDownloaded {
		dt := now.Sub(s.previousAt)
		s.uploadRate = ptr(rate(uploaded-s.previousUploaded, dt))
		s.downloadRate = ptr(rate(downloaded-s.previousDownloaded, dt))
		s.rateReady = true
	} else if !s.previousSet || !now.Equal(s.previousAt) {
		s.rateReady = false
		s.uploadRate, s.downloadRate = nil, nil
	}
	s.previousAt, s.previousUploaded, s.previousDownloaded = now, uploaded, downloaded
	s.previousSet = true
	out := &ConnectionStatistics{SchemaVersion: 1, SessionID: sessionID, ElapsedMilliseconds: ms, Scope: s.scope}
	if s.scope == "native-transport" && !s.nativeReady {
		return out
	}
	out.UploadedBytes, out.DownloadedBytes = ptr(uploaded), ptr(downloaded)
	if s.rateReady {
		out.UploadBytesPerSecond = ptr(*s.uploadRate)
		out.DownloadBytesPerSecond = ptr(*s.downloadRate)
	}
	return out
}

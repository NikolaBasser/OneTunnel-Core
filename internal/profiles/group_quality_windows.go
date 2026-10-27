package profiles

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const groupQualityWindow = 30 * time.Minute
const groupQualitySamples = 8
const groupQualityProfiles = 256

type groupQualitySample struct {
	at      time.Time
	success bool
	latency int64
}

type groupQualitySeries struct {
	key     [32]byte
	samples []groupQualitySample
}

type GroupQualitySummary struct {
	Samples, Successful, TimingSamples int
	MedianHTTPSMilliseconds            *int64 `json:",omitempty"`
	MinimumHTTPSMilliseconds           *int64 `json:",omitempty"`
	MaximumHTTPSMilliseconds           *int64 `json:",omitempty"`
	Label                              string
}

func groupQualityKey(profile Profile) [32]byte {
	// Native checks measure DNS exchanges, not comparable public HTTPS requests.
	if profile.Protocol < 2 {
		return [32]byte{}
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return [32]byte{}
	}
	defer clear(data)
	return sha256.Sum256(data)
}

func currentGroupSamples(series groupQualitySeries, now time.Time) []groupQualitySample {
	var samples []groupQualitySample
	for _, sample := range series.samples {
		if !sample.at.After(now) && now.Sub(sample.at) < groupQualityWindow {
			samples = append(samples, sample)
		}
	}
	return samples
}

func (a *Application) recordGroupQuality(row GroupCheckRow, now time.Time) {
	if row.ID == "" || row.qualityKey == ([32]byte{}) || !row.NetworkTest || row.DNSLatencyMilliseconds != nil || row.Success && (row.HTTPSLatencyMilliseconds == nil || *row.HTTPSLatencyMilliseconds < 0) {
		return
	}
	if a.groupQuality == nil {
		a.groupQuality = make(map[string]groupQualitySeries)
	}
	for id, series := range a.groupQuality {
		series.samples = currentGroupSamples(series, now)
		if len(series.samples) == 0 {
			delete(a.groupQuality, id)
		} else {
			a.groupQuality[id] = series
		}
	}
	series := a.groupQuality[row.ID]
	if series.key != row.qualityKey {
		series = groupQualitySeries{key: row.qualityKey}
	}
	if _, exists := a.groupQuality[row.ID]; !exists && len(a.groupQuality) >= groupQualityProfiles {
		oldest := ""
		for id, candidate := range a.groupQuality {
			if oldest == "" || candidate.samples[len(candidate.samples)-1].at.Before(a.groupQuality[oldest].samples[len(a.groupQuality[oldest].samples)-1].at) || candidate.samples[len(candidate.samples)-1].at.Equal(a.groupQuality[oldest].samples[len(a.groupQuality[oldest].samples)-1].at) && id < oldest {
				oldest = id
			}
		}
		delete(a.groupQuality, oldest)
	}
	at := row.qualityAt
	if at.IsZero() {
		at = now
	}
	if at.After(now) || now.Sub(at) >= groupQualityWindow {
		return
	}
	sample := groupQualitySample{at: at, success: row.Success}
	if row.Success {
		sample.latency = *row.HTTPSLatencyMilliseconds
	}
	series.samples = append(series.samples, sample)
	if len(series.samples) > groupQualitySamples {
		series.samples = series.samples[len(series.samples)-groupQualitySamples:]
	}
	a.groupQuality[row.ID] = series
}

func (a *Application) groupQualitySummary(row GroupCheckRow, now time.Time) *GroupQualitySummary {
	series, exists := a.groupQuality[row.ID]
	if !exists || series.key != row.qualityKey {
		return nil
	}
	samples := currentGroupSamples(series, now)
	if len(samples) == 0 {
		return nil
	}
	view := &GroupQualitySummary{Samples: len(samples)}
	var timings []int64
	for _, sample := range samples {
		if sample.success {
			view.Successful++
			timings = append(timings, sample.latency)
		}
	}
	view.TimingSamples = len(timings)
	view.Label = fmt.Sprintf("Recent checks: %d/%d successful (last 30 minutes, this app session)", view.Successful, view.Samples)
	if len(timings) > 0 {
		sort.Slice(timings, func(i, j int) bool { return timings[i] < timings[j] })
		minimum, maximum := timings[0], timings[len(timings)-1]
		median := timings[len(timings)/2]
		if len(timings)%2 == 0 {
			lower := timings[len(timings)/2-1]
			median = lower + (median-lower)/2
		}
		view.MedianHTTPSMilliseconds, view.MinimumHTTPSMilliseconds, view.MaximumHTTPSMilliseconds = &median, &minimum, &maximum
		view.Label += fmt.Sprintf("; %d HTTPS timing samples, median %d ms, observed range %d–%d ms", len(timings), median, minimum, maximum)
	}
	return view
}

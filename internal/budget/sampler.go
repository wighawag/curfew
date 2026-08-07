package budget

import (
	"time"
)

// DefaultInterval is how often usage is accounted for. It matches the daemon's
// reconcile tick, and a budget is expressed in minutes, so a minute is the
// natural grain.
const DefaultInterval = time.Minute

// Sampler turns CUMULATIVE nftables counters into per-interval activity.
//
// It exists because a counter is a running total, not a tally: deciding
// whether an interval was active means remembering the previous reading and
// subtracting. Three things make that harder than it sounds, and all three are
// handled here rather than at the call site.
//
//   - The counter goes BACKWARDS after a reboot, a rebuild of the accounting
//     table, or a manual `nft flush`. A naive subtraction then yields either a
//     negative or an enormous delta, so it would either credit a child a free
//     interval or charge them one they did not use. A backwards reading
//     re-baselines and the interval is SKIPPED.
//
//   - The accounting table's own generation is reported by the accountant, so
//     a reset WE caused is known rather than inferred. The backwards check
//     stays as well, because a reset somebody else caused is not announced.
//
//   - Sampling is not evenly spaced. Reconcile runs on a tick but also on
//     every button press, so counting "one interval per call" would let a
//     parent tapping buttons burn a child's whole afternoon. Sampling is
//     therefore gated on real elapsed time and credits the time it actually
//     observed.
//
// The previous reading is deliberately NOT persisted. It baselines a kernel
// counter that does not survive a reboot either, so persisting it would
// preserve a number whose meaning had already gone. The cost is that one
// interval is skipped after a restart, which is a minute of unbilled use, in
// the child's favour, once per restart.
type Sampler struct {
	interval   time.Duration
	threshold  uint64
	lastAt     time.Time
	generation uint64
	last       map[string]uint64
}

// NewSampler builds a sampler. An interval or threshold of zero takes the
// default; both are injectable so a packet-path test can drive a budget to
// exhaustion in seconds against the REAL counter rather than a fake one.
func NewSampler(interval time.Duration, threshold uint64) *Sampler {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if threshold == 0 {
		threshold = DefaultActivityThreshold
	}
	return &Sampler{interval: interval, threshold: threshold, last: map[string]uint64{}}
}

// Interval reports the sampling interval.
func (s *Sampler) Interval() time.Duration { return s.interval }

// Threshold reports the activity threshold in bytes per minute.
func (s *Sampler) Threshold() uint64 { return s.threshold }

// bytesFor scales the per-minute threshold to the interval actually observed.
//
// The threshold is configured as a RATE because that is what a person can
// calibrate ("this device sends about 5 KB a minute when it is asleep"), and
// scaling here is what keeps that number meaning the same thing when the
// interval is shortened for a test or lengthened on the router.
func (s *Sampler) bytesFor(elapsed time.Duration) uint64 {
	scaled := float64(s.threshold) * elapsed.Seconds() / 60
	if scaled < 1 {
		// Never zero: a zero threshold would make any traffic at all count,
		// including the single keepalive packet ADR 0001 exists to ignore.
		return 1
	}
	return uint64(scaled)
}

// Observation is one profile's result for one interval.
type Observation struct {
	// Active is whether traffic exceeded the threshold.
	Active bool
	// Bytes is the delta observed, which the page reports so the threshold can
	// be calibrated against the devices actually in the house.
	Bytes uint64
}

// Sample reads the counters and reports which profiles were active.
//
// counters are cumulative byte totals by profile; generation changes whenever
// the accountant rebuilt the table and therefore zeroed them. ok is false when
// nothing was observed: too little time has passed, or this is the first
// reading and there is nothing to subtract from.
func (s *Sampler) Sample(now time.Time, generation uint64, counters map[string]uint64) (
	obs map[string]Observation, elapsed time.Duration, ok bool) {

	if generation != s.generation {
		// The counters were reset by us. Everything we remember about them is
		// meaningless, so re-baseline rather than subtract across the reset.
		s.generation = generation
		s.last = map[string]uint64{}
		s.lastAt = now
		s.baseline(counters)
		return nil, 0, false
	}
	if s.lastAt.IsZero() {
		s.lastAt = now
		s.baseline(counters)
		return nil, 0, false
	}
	elapsed = now.Sub(s.lastAt)
	if elapsed < s.interval {
		// Not a sample. Deliberately leaves the previous reading alone, so the
		// next real sample still spans a full interval.
		return nil, 0, false
	}

	want := s.bytesFor(elapsed)
	obs = make(map[string]Observation, len(counters))
	for name, cur := range counters {
		prev, seen := s.last[name]
		switch {
		case !seen:
			// A profile whose counter has only just appeared. There is nothing
			// to subtract from, so it is baselined and skipped, exactly like a
			// reset.
		case cur < prev:
			// The counter went BACKWARDS: a reboot, a rebuild, or somebody
			// flushing by hand. Skip the interval rather than crediting a free
			// one or charging an enormous one.
		default:
			delta := cur - prev
			obs[name] = Observation{Active: delta >= want, Bytes: delta}
		}
	}
	s.lastAt = now
	s.baseline(counters)
	return obs, elapsed, true
}

// baseline replaces the remembered readings with the current ones, dropping
// any profile whose counter has gone (a profile deleted, or renamed).
func (s *Sampler) baseline(counters map[string]uint64) {
	next := make(map[string]uint64, len(counters))
	for k, v := range counters {
		next[k] = v
	}
	s.last = next
}

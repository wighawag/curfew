package budget

import (
	"testing"
	"time"
)

// The sampler turns a cumulative counter into per-interval activity, and every
// test here is a case where getting the subtraction wrong charges or credits a
// child for an interval nobody measured.

const kib = 1024

func TestTheFirstReadingIsABaselineAndChargesNothing(t *testing.T) {
	s := NewSampler(time.Minute, 50*kib)
	now := at("09:00")
	if _, _, ok := s.Sample(now, 0, map[string]uint64{"eli": 1_000_000}); ok {
		t.Error("the first reading has nothing to subtract from and must not be a sample")
	}
	// And it really did take the baseline, rather than leaving the whole
	// million bytes to be charged next time.
	obs, _, ok := s.Sample(now.Add(time.Minute), 0, map[string]uint64{"eli": 1_000_100})
	if !ok {
		t.Fatal("the second reading should be a sample")
	}
	if obs["eli"].Bytes != 100 {
		t.Errorf("delta = %d, want 100: the baseline was not taken", obs["eli"].Bytes)
	}
	if obs["eli"].Active {
		t.Error("100 bytes in a minute is not a child using the internet")
	}
}

func TestTrafficAboveTheThresholdIsActive(t *testing.T) {
	s := NewSampler(time.Minute, 50*kib)
	now := at("09:00")
	s.Sample(now, 0, map[string]uint64{"eli": 0})
	obs, elapsed, ok := s.Sample(now.Add(time.Minute), 0, map[string]uint64{"eli": 60 * kib})
	if !ok {
		t.Fatal("want a sample")
	}
	if elapsed != time.Minute {
		t.Errorf("elapsed = %s, want 1m", elapsed)
	}
	if !obs["eli"].Active {
		t.Errorf("60 KiB in a minute is above a 50 KiB threshold, got %+v", obs["eli"])
	}
}

// The trap: a counter that goes BACKWARDS after a reboot, a table rebuild or a
// manual flush. A naive subtraction yields a negative or an enormous delta.
func TestABackwardsCounterSkipsTheIntervalRatherThanChargingIt(t *testing.T) {
	s := NewSampler(time.Minute, 50*kib)
	now := at("09:00")
	s.Sample(now, 0, map[string]uint64{"eli": 5_000_000})
	// Same generation, so this is a reset we did NOT cause: somebody ran
	// `nft flush ruleset`, or the box rebooted under us.
	obs, _, ok := s.Sample(now.Add(time.Minute), 0, map[string]uint64{"eli": 1_000})
	if !ok {
		t.Fatal("the interval itself is still a sample; only the profile is skipped")
	}
	if _, present := obs["eli"]; present {
		t.Errorf("a backwards counter must be skipped, got %+v", obs["eli"])
	}
	// And it re-baselined, so the NEXT interval is measured normally rather
	// than charging the whole counter over again.
	obs, _, ok = s.Sample(now.Add(2*time.Minute), 0, map[string]uint64{"eli": 1_500})
	if !ok {
		t.Fatal("want a sample")
	}
	if obs["eli"].Bytes != 500 {
		t.Errorf("delta = %d, want 500 after re-baselining", obs["eli"].Bytes)
	}
}

// A reset WE caused is announced by the generation, so it is known rather than
// inferred. This matters because a rebuild can leave the counter HIGHER than
// before if enough traffic flows in between, which the backwards check alone
// would miss.
func TestAGenerationChangeDropsTheBaselineEvenWhenTheCounterWentUp(t *testing.T) {
	s := NewSampler(time.Minute, 1)
	now := at("09:00")
	s.Sample(now, 7, map[string]uint64{"eli": 100})
	// The accountant rebuilt: counters zeroed, then 90 KiB flowed. The raw
	// reading is far higher than the last one, so nothing about it looks
	// wrong, and subtracting would charge an interval that spans a reset.
	obs, _, ok := s.Sample(now.Add(time.Minute), 8, map[string]uint64{"eli": 90 * kib})
	if ok {
		t.Errorf("a generation change must re-baseline, not sample: got %+v", obs)
	}
	obs, _, ok = s.Sample(now.Add(2*time.Minute), 8, map[string]uint64{"eli": 90*kib + 10})
	if !ok {
		t.Fatal("want a sample after re-baselining")
	}
	if obs["eli"].Bytes != 10 {
		t.Errorf("delta = %d, want 10", obs["eli"].Bytes)
	}
}

// Reconcile runs on every button press as well as on the tick. Counting one
// interval per call would let a parent tapping buttons burn an afternoon.
func TestSamplingIsGatedOnRealElapsedTime(t *testing.T) {
	s := NewSampler(time.Minute, 50*kib)
	now := at("09:00")
	s.Sample(now, 0, map[string]uint64{"eli": 0})
	for i := range 20 {
		at := now.Add(time.Duration(i) * time.Second)
		if _, _, ok := s.Sample(at, 0, map[string]uint64{"eli": uint64(i) * 100 * kib}); ok {
			t.Fatalf("sampled after only %s; a budget must not advance per call", at.Sub(now))
		}
	}
	// And the deferred sample still spans the whole minute rather than the
	// last fraction of it, so nothing is lost by the gating.
	obs, elapsed, ok := s.Sample(now.Add(time.Minute), 0, map[string]uint64{"eli": 60 * kib})
	if !ok {
		t.Fatal("want a sample once the interval has really passed")
	}
	if elapsed != time.Minute {
		t.Errorf("elapsed = %s, want the full minute", elapsed)
	}
	if obs["eli"].Bytes != 60*kib {
		t.Errorf("delta = %d, want the whole interval's traffic", obs["eli"].Bytes)
	}
}

// The threshold is a RATE, so it keeps its meaning when the interval changes.
// A packet-path test shortens the interval to seconds; without scaling, the
// same threshold would then be impossible to cross.
func TestTheThresholdScalesWithTheIntervalActuallyObserved(t *testing.T) {
	s := NewSampler(time.Second, 60*kib) // 60 KiB/min == 1 KiB/s
	now := at("09:00")
	s.Sample(now, 0, map[string]uint64{"eli": 0, "tia": 0})
	obs, _, ok := s.Sample(now.Add(time.Second), 0, map[string]uint64{
		"eli": 2 * kib, // 2 KiB in a second: well above 1 KiB/s
		"tia": 100,     // 100 bytes in a second: well below
	})
	if !ok {
		t.Fatal("want a sample")
	}
	if !obs["eli"].Active {
		t.Error("2 KiB in one second is above a 60 KiB/min threshold")
	}
	if obs["tia"].Active {
		t.Error("100 bytes in one second is below a 60 KiB/min threshold")
	}
}

func TestAZeroScaledThresholdNeverBecomesAnythingGoes(t *testing.T) {
	// A very short interval against a modest rate scales below one byte. It
	// must not round to zero, or a single keepalive packet would count as a
	// child using the internet, which is exactly what ADR 0001 rules out.
	s := NewSampler(time.Millisecond, 1)
	now := at("09:00")
	s.Sample(now, 0, map[string]uint64{"eli": 0})
	obs, _, ok := s.Sample(now.Add(time.Millisecond), 0, map[string]uint64{"eli": 0})
	if !ok {
		t.Fatal("want a sample")
	}
	if obs["eli"].Active {
		t.Error("zero bytes must never count as activity")
	}
}

func TestANewProfileIsBaselinedNotCharged(t *testing.T) {
	s := NewSampler(time.Minute, 50*kib)
	now := at("09:00")
	s.Sample(now, 0, map[string]uint64{"eli": 0})
	obs, _, ok := s.Sample(now.Add(time.Minute), 0, map[string]uint64{"eli": 10, "tia": 900 * kib})
	if !ok {
		t.Fatal("want a sample")
	}
	if _, present := obs["tia"]; present {
		t.Error("a profile seen for the first time has no baseline and must be skipped, not charged")
	}
}

func TestADepartedProfileIsForgotten(t *testing.T) {
	s := NewSampler(time.Minute, 50*kib)
	now := at("09:00")
	s.Sample(now, 0, map[string]uint64{"eli": 1000, "tia": 2000})
	s.Sample(now.Add(time.Minute), 0, map[string]uint64{"eli": 2000})
	// tia comes back with a LOWER counter than it left with. If the sampler
	// had kept the old reading this would look like a backwards jump forever.
	obs, _, ok := s.Sample(now.Add(2*time.Minute), 0, map[string]uint64{"eli": 3000, "tia": 10})
	if !ok {
		t.Fatal("want a sample")
	}
	if _, present := obs["tia"]; present {
		t.Error("a returning profile must be baselined afresh")
	}
	obs, _, _ = s.Sample(now.Add(3*time.Minute), 0, map[string]uint64{"eli": 4000, "tia": 60 * kib})
	if !obs["tia"].Active {
		t.Error("once baselined again, the returning profile must be measured normally")
	}
}

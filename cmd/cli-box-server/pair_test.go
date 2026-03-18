package main

import (
	"testing"
	"time"
)

func TestPairingRateLimiterBlocksGloballyAfterTooManyFailures(t *testing.T) {
	limiter := NewPairingRateLimiter()
	now := time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC)

	for range pairingMaxAttempts {
		if !limiter.Allow(now) {
			t.Fatal("limiter blocked before max attempts")
		}
		limiter.RecordFailure(now)
	}

	if limiter.Allow(now) {
		t.Fatal("limiter allowed attempts after max failures")
	}

	if !limiter.Allow(now.Add(pairingAttemptWindow + time.Second)) {
		t.Fatal("limiter should reset after the time window")
	}
}

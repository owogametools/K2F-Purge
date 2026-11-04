package service

import (
	"runtime"
	"testing"
)

func TestSecretScanRequiresExposure(t *testing.T) {
	s, err := New("K2F PURGE", "test", runtime.GOOS, runtime.GOARCH, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SecretScan(nil); err == nil {
		t.Fatal("SecretScan ran without an exposure result")
	}
}

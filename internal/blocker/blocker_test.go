package blocker

import "testing"

func TestClassifyRegion(t *testing.T) {
	if r := ClassifyRegion("43.174.251.100", 45); r != "Европа" {
		t.Fatalf("expected Европа for 43.174.251.100, got %s", r)
	}
	if r := ClassifyRegion("119.28.109.10", 180); r != "Азия" {
		t.Fatalf("expected Азия for 119.28.109.10, got %s", r)
	}
	if r := ClassifyRegion("162.62.221.5", 130); r != "США" {
		t.Fatalf("expected США for 162.62.221.5, got %s", r)
	}
}

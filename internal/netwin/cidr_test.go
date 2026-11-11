package netwin

import "testing"

func TestNormalizePrefixesCollapsesAndExcludesEndpoint(t *testing.T) {
	in := []string{
		"43.174.250.0/25",
		"43.174.250.128/25",
		"162.159.195.0/24",
	}
	got := NormalizePrefixes(in, "162.159.195.4")
	if !InPrefixes("43.174.250.99", got) {
		t.Fatalf("expected collapsed 43.174.250.0/24 to contain .99, got %v", got)
	}
	if InPrefixes("162.159.195.4", got) {
		t.Fatalf("expected tunnel endpoint 162.159.195.4 to be excluded from routes, got %v", got)
	}
	if !InPrefixes("162.159.195.5", got) {
		t.Fatalf("expected sibling 162.159.195.5 to remain routed, got %v", got)
	}
}

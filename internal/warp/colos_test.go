package warp

import "testing"

func TestLookupColo(t *testing.T) {
	code, city, country := LookupColo("fra05")
	if code != "FRA" || city != "Франкфурт" || country != "Германия" {
		t.Fatalf("unexpected FRA lookup: %s %s %s", code, city, country)
	}
	code2, city2, _ := LookupColo("HEL")
	if code2 != "HEL" || city2 != "Хельсинки" {
		t.Fatalf("unexpected HEL lookup: %s %s", code2, city2)
	}
}

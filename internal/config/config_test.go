package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyPythonMigration(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("ABIROUTE_DATA_DIR", tmp)

	legacy := `{
  "warp": {
    "private_key": "priv123",
    "public_key": "pub123",
    "peer_public_key": "peer123",
    "v4": "172.16.0.2",
    "id": "dev-1",
    "token": "tok-1",
    "created": "10.11.2026 12:00"
  },
  "ranges": ["43.174.251.0/24"],
  "prefix": 20,
  "mtu": 1280
}`
	if err := os.WriteFile(filepath.Join(tmp, "settings.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	store := LoadStore()
	st := store.Get()
	if st.Warp == nil || st.Warp.PrivateKey != "priv123" || st.Warp.Source != "migrated" {
		t.Fatalf("expected legacy WARP account to migrate, got %+v", st.Warp)
	}
	if st.SubnetPrefix != 20 || len(st.LearnedRanges["abi"]) != 1 {
		t.Fatalf("expected prefix=20 and learned ranges migrated, got prefix=%d ranges=%v", st.SubnetPrefix, st.LearnedRanges)
	}
}

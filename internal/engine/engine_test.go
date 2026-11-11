package engine

import (
	"abiroute/internal/config"
	"testing"
)

func TestEngineSelectGameAndCustomGame(t *testing.T) {
	t.Setenv("ABIROUTE_DATA_DIR", t.TempDir())
	store := config.LoadStore()
	eng := New(store, nil)
	defer eng.Shutdown()

	st := eng.GetState()
	if st.ActiveGame.ID != "abi" {
		t.Fatalf("expected default active game abi, got %s", st.ActiveGame.ID)
	}
	if len(st.Catalog) < 6 {
		t.Fatalf("expected >=6 builtin games in catalog, got %d", len(st.Catalog))
	}

	st2, err := eng.AddCustomGame("Deadlock", "project8.exe", "155.133.248.0/24")
	if err != nil {
		t.Fatalf("AddCustomGame failed: %v", err)
	}
	if st2.ActiveGame.Name != "Deadlock" || len(st2.ActiveGame.Processes) != 1 || st2.ActiveGame.Processes[0] != "project8.exe" {
		t.Fatalf("unexpected custom game state: %+v", st2.ActiveGame)
	}
}

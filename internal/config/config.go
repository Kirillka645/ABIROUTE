package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

const AppVersion = "4.0.0"

type WarpAccount struct {
	PrivateKey    string `json:"privateKey"`
	PublicKey     string `json:"publicKey"`
	PeerPublicKey string `json:"peerPublicKey"`
	IPv4          string `json:"ipv4"`
	IPv6          string `json:"ipv6"`
	DeviceID      string `json:"deviceId"`
	Token         string `json:"token"`
	Created       string `json:"created"`
	Source        string `json:"source"`
}

type MasqueAccount struct {
	PrivateKeyDERB64  string `json:"privateKeyDerB64"`
	PublicKeyPKIXB64  string `json:"publicKeyPkixB64"`
	EndpointV4        string `json:"endpointV4"`
	EndpointH2V4      string `json:"endpointH2V4"`
	EndpointPubKeyPEM string `json:"endpointPubKeyPem"`
	IPv4              string `json:"ipv4"`
	IPv6              string `json:"ipv6"`
	DeviceID          string `json:"deviceId"`
	Token             string `json:"token"`
	Created           string `json:"created"`
}

type CustomTunnelConfig struct {
	Name          string            `json:"name"`
	PrivateKey    string            `json:"privateKey"`
	PublicKey     string            `json:"publicKey"`
	PeerPublicKey string            `json:"peerPublicKey"`
	PresharedKey  string            `json:"presharedKey,omitempty"`
	AddressV4     string            `json:"addressV4"`
	Endpoint      string            `json:"endpoint"`
	MTU           int               `json:"mtu"`
	Jc            int               `json:"jc"`
	Jmin          int               `json:"jmin"`
	Jmax          int               `json:"jmax"`
	S             map[string]int    `json:"s,omitempty"`
	H             map[string]string `json:"h,omitempty"`
	I             map[string]string `json:"i,omitempty"`
	Created       string            `json:"created"`
}

type NodeInfo struct {
	Endpoint     string `json:"endpoint"`
	ColoCode     string `json:"coloCode"`
	City         string `json:"city"`
	Country      string `json:"country"`
	HandshakeMs  int    `json:"handshakeMs"`
	TunnelPingMs int    `json:"tunnelPingMs"`
	JitterMs     int    `json:"jitterMs"`
	LossPct      int    `json:"lossPct"`
	Score        int    `json:"score"`
}

type CustomGame struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	ShortCode    string   `json:"shortCode"`
	Category     string   `json:"category"`
	Processes    []string `json:"processes"`
	PresetRanges []string `json:"presetRanges"`
	IgnoreRanges []string `json:"ignoreRanges"`
}

type SeenServer struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Proto    string `json:"proto"` // "UDP" | "TCP"
	Role     string `json:"role"`  // "Сервер рейда" | "Лобби / Матчмейкинг"
	DirectMs int    `json:"directMs"`
	TunnelMs int    `json:"tunnelMs"`
	Routed   bool   `json:"routed"`
	LastSeen int64  `json:"lastSeen"`
}

type Settings struct {
	ActiveGameID     string                  `json:"activeGameId"`
	Protocol         string                  `json:"protocol"` // "auto" | "awg_quic" | "awg_dns" | "awg_sip" | "awg_junk" | "masque_h3" | "masque_h2" | "custom"
	SelectedEndpoint string                  `json:"selectedEndpoint"`
	MimicSNI         string                  `json:"mimicSni"`
	MTU              int                     `json:"mtu"`
	SubnetPrefix     int                     `json:"subnetPrefix"`
	RaidProtection   bool                    `json:"raidProtection"`
	AutoFailover     bool                    `json:"autoFailover"`
	AutoLearn        bool                    `json:"autoLearn"`
	CloseToTray      bool                    `json:"closeToTray"`
	Warp             *WarpAccount            `json:"warp,omitempty"`
	Masque           *MasqueAccount          `json:"masque,omitempty"`
	CustomTunnel     *CustomTunnelConfig     `json:"customTunnel,omitempty"`
	Nodes            []NodeInfo              `json:"nodes"`
	CustomGames      []CustomGame            `json:"customGames"`
	LearnedRanges    map[string][]string     `json:"learnedRanges"`
	SeenServers      map[string][]SeenServer `json:"seenServers"`
}

type Store struct {
	mu   sync.RWMutex
	dir  string
	path string
	data Settings
}

func DataDir() string {
	if custom := os.Getenv("ABIROUTE_DATA_DIR"); custom != "" {
		return custom
	}
	appData := os.Getenv("APPDATA")
	if appData == "" {
		home, _ := os.UserHomeDir()
		appData = home
	}
	return filepath.Join(appData, "ABIRoute")
}

func DefaultSettings() Settings {
	return Settings{
		ActiveGameID:     "abi",
		Protocol:         "auto",
		SelectedEndpoint: "auto",
		MimicSNI:         "www.google.com",
		MTU:              1280,
		SubnetPrefix:     24,
		RaidProtection:   true,
		AutoFailover:     true,
		AutoLearn:        true,
		CloseToTray:      true,
		Nodes:            []NodeInfo{},
		CustomGames:      []CustomGame{},
		LearnedRanges:    map[string][]string{},
		SeenServers:      map[string][]SeenServer{},
	}
}

func LoadStore() *Store {
	dir := DataDir()
	path := filepath.Join(dir, "settings_v4.json")
	st := DefaultSettings()

	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &st)
	} else {
		migrateLegacyPythonSettings(dir, &st)
	}
	normalizeSettings(&st)

	s := &Store{
		dir:  dir,
		path: path,
		data: st,
	}
	_ = s.Save()
	return s
}

func normalizeSettings(st *Settings) {
	if st.ActiveGameID == "" {
		st.ActiveGameID = "abi"
	}
	if st.Protocol == "" {
		st.Protocol = "auto"
	}
	if st.SelectedEndpoint == "" {
		st.SelectedEndpoint = "auto"
	}
	if st.MimicSNI == "" {
		st.MimicSNI = "www.google.com"
	}
	if st.MTU < 1200 || st.MTU > 1420 {
		st.MTU = 1280
	}
	if st.SubnetPrefix != 16 && st.SubnetPrefix != 20 && st.SubnetPrefix != 24 {
		st.SubnetPrefix = 24
	}
	if st.Nodes == nil {
		st.Nodes = []NodeInfo{}
	}
	if st.CustomGames == nil {
		st.CustomGames = []CustomGame{}
	}
	if st.LearnedRanges == nil {
		st.LearnedRanges = map[string][]string{}
	}
	if st.SeenServers == nil {
		st.SeenServers = map[string][]SeenServer{}
	}
}

func migrateLegacyPythonSettings(dir string, dst *Settings) {
	legacyPath := filepath.Join(dir, "settings.json")
	raw, err := os.ReadFile(legacyPath)
	if err != nil {
		return
	}
	var legacy struct {
		Warp *struct {
			PrivateKey    string `json:"private_key"`
			PublicKey     string `json:"public_key"`
			PeerPublicKey string `json:"peer_public_key"`
			V4            string `json:"v4"`
			V6            string `json:"v6"`
			ID            string `json:"id"`
			Token         string `json:"token"`
			Created       string `json:"created"`
			Source        string `json:"source"`
			Custom        bool   `json:"custom"`
			Endpoint      string `json:"endpoint"`
		} `json:"warp"`
		Endpoint string   `json:"endpoint"`
		Ranges   []string `json:"ranges"`
		Prefix   int      `json:"prefix"`
		MTU      int      `json:"mtu"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return
	}
	if legacy.Warp != nil && legacy.Warp.PrivateKey != "" && !legacy.Warp.Custom {
		dst.Warp = &WarpAccount{
			PrivateKey:    legacy.Warp.PrivateKey,
			PublicKey:     legacy.Warp.PublicKey,
			PeerPublicKey: legacy.Warp.PeerPublicKey,
			IPv4:          legacy.Warp.V4,
			IPv6:          legacy.Warp.V6,
			DeviceID:      legacy.Warp.ID,
			Token:         legacy.Warp.Token,
			Created:       legacy.Warp.Created,
			Source:        "migrated",
		}
	}
	if len(legacy.Ranges) > 0 {
		dst.LearnedRanges["abi"] = legacy.Ranges
	}
	if legacy.Prefix == 16 || legacy.Prefix == 20 || legacy.Prefix == 24 {
		dst.SubnetPrefix = legacy.Prefix
	}
	if legacy.MTU >= 1200 && legacy.MTU <= 1420 {
		dst.MTU = legacy.MTU
	}
}

func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, _ := json.Marshal(s.data)
	var copySt Settings
	_ = json.Unmarshal(raw, &copySt)
	normalizeSettings(&copySt)
	return copySt
}

func (s *Store) Update(fn func(*Settings)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
	normalizeSettings(&s.data)
	return s.saveLocked()
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

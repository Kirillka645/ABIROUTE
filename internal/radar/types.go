package radar

type EndpointHit struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Proto    string `json:"proto"` // "UDP" | "TCP"
	Role     string `json:"role"`
	Packets  int    `json:"packets"`
	LastSeen int64  `json:"lastSeen"`
}

type Snapshot struct {
	GameRunning bool          `json:"gameRunning"`
	ActivePIDs  []uint32      `json:"activePids"`
	ETWActive   bool          `json:"etwActive"`
	RawFallback bool          `json:"rawFallback"`
	Hits        []EndpointHit `json:"hits"`
}

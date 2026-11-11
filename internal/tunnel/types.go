package tunnel

const InterfaceName = "ABIRoute"

type Stats struct {
	RxBytes          uint64 `json:"rxBytes"`
	TxBytes          uint64 `json:"txBytes"`
	LastHandshakeSec int64  `json:"lastHandshakeSec"`
	Connected        bool   `json:"connected"`
}

type Runner interface {
	UpdateRoutes(desiredPrefixes []string) error
	AppliedRoutes() []string
	Stats() Stats
	Close() error
}

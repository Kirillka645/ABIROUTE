//go:build !windows

package netwin

type PhysicalNIC struct {
	IP          string `json:"ip"`
	Gateway     string `json:"gateway"`
	IfIndex     uint32 `json:"ifIndex"`
	AdapterName string `json:"adapterName"`
}

func IsAdmin() bool { return true }

func DefaultPhysicalInterface() (*PhysicalNIC, error) {
	return &PhysicalNIC{IP: "192.168.1.10", Gateway: "192.168.1.1", IfIndex: 1, AdapterName: "eth0"}, nil
}

func ConfigureTunInterface(ifaceName, ipv4 string, mtu int) error { return nil }

func SyncRoutes(ifaceName, endpointIP string, phys *PhysicalNIC, desiredPrefixes []string, prevPrefixes []string) error {
	return nil
}

func CleanupRoutes(ifaceName, endpointIP string, prefixes []string) {}

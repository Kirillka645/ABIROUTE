package proxy

import (
	"encoding/json"
	"testing"
)

func TestParseVLESSRealityAndHysteria2(t *testing.T) {
	vlessURI := "vless://550e8400-e29b-41d4-a716-446655440000@198.51.100.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=testPublicKey123&sid=01ab&type=tcp#DE-Frankfurt-Reality"
	parsed, err := ParseURI(vlessURI, "")
	if err != nil {
		t.Fatalf("ParseURI(vless) failed: %v", err)
	}
	if parsed.Node.Scheme != "vless" || parsed.Security != "reality" || parsed.PublicKey != "testPublicKey123" || parsed.Node.Name != "DE-Frankfurt-Reality" {
		t.Fatalf("unexpected vless parsed: %+v", parsed)
	}

	cfgBytes, err := BuildSingBoxConfig(parsed, "ABIRoute", 1280, "192.168.1.50", 9090)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig(vless) failed: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(cfgBytes, &obj); err != nil {
		t.Fatalf("invalid JSON from BuildSingBoxConfig: %v", err)
	}

	hy2URI := "hy2://mySecretPass@203.0.113.77:443?sni=bing.com&obfs=salamander&obfs-password=obf123&insecure=1#FI-Helsinki-HY2"
	hy2, err := ParseURI(hy2URI, "")
	if err != nil {
		t.Fatalf("ParseURI(hy2) failed: %v", err)
	}
	if hy2.Node.Scheme != "hysteria2" || hy2.ObfsType != "salamander" || !hy2.Insecure {
		t.Fatalf("unexpected hy2 parsed: %+v", hy2)
	}
	if _, err := BuildSingBoxConfig(hy2, "ABIRoute", 1280, "192.168.1.50", 0); err != nil {
		t.Fatalf("BuildSingBoxConfig(hy2) failed: %v", err)
	}
}

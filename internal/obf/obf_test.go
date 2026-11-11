package obf

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildQUICInitialAndCPS(t *testing.T) {
	pkt, err := BuildQUICInitial("www.google.com")
	if err != nil {
		t.Fatalf("BuildQUICInitial failed: %v", err)
	}
	if len(pkt) < 1200 {
		t.Fatalf("expected QUIC Initial >= 1200 bytes per RFC 9000, got %d", len(pkt))
	}
	if (pkt[0] & 0x80) == 0 {
		t.Fatalf("expected QUIC long header bit set, got 0x%02x", pkt[0])
	}

	spec := ToCPS(pkt) + " <r 12> <rc 6> <rd 4> <t>"
	rendered, err := RenderCPS(spec)
	if err != nil {
		t.Fatalf("RenderCPS failed: %v", err)
	}
	wantLen := len(pkt) + 12 + 6 + 4 + 4
	if len(rendered) != wantLen {
		t.Fatalf("expected rendered length %d, got %d", wantLen, len(rendered))
	}
}

func TestParseAndBuildConf(t *testing.T) {
	sample := `[Interface]
PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
Address = 10.8.1.2/32
MTU = 1280
Jc = 6
Jmin = 40
Jmax = 90
I1 = <b 0xc000000001><r 16>

[Peer]
PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
Endpoint = 203.0.113.5:51820 # comment
AllowedIPs = 0.0.0.0/0
`
	parsed, err := ParseConf(sample, "")
	if err != nil {
		t.Fatalf("ParseConf failed: %v", err)
	}
	if parsed.AddressV4 != "10.8.1.2" || parsed.Endpoint != "203.0.113.5:51820" || parsed.Jc != 6 {
		t.Fatalf("unexpected parsed fields: %+v", parsed)
	}
	if parsed.I["I1"] == "" {
		t.Fatalf("expected I1 to be preserved")
	}

	out := BuildConf(parsed.PrivateKey, parsed.AddressV4, parsed.PeerPublicKey, "", parsed.Endpoint, 1280, BuildProfile("awg_dns", "cloudflare.com"), []string{"43.174.251.0/24"})
	if !strings.Contains(out, "AllowedIPs = 43.174.251.0/24") {
		t.Fatalf("expected AllowedIPs in built conf: %s", out)
	}
}

func TestParseVPNURI(t *testing.T) {
	innerConf := `[Interface]
PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
Address = 10.66.66.2/32
Jc = 4
Jmin = 40
Jmax = 70

[Peer]
PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
Endpoint = 198.51.100.42:44321
`
	containerJSON, _ := json.Marshal(map[string]any{
		"description": "My Amnezia DE",
		"hostName":    "198.51.100.42",
		"containers": []map[string]any{
			{
				"container": "amnezia-awg",
				"awg": map[string]any{
					"last_config": innerConf,
				},
			},
		},
	})

	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	_, _ = zw.Write(containerJSON)
	_ = zw.Close()

	qtPayload := make([]byte, 4+zbuf.Len())
	binary.BigEndian.PutUint32(qtPayload[:4], uint32(len(containerJSON)))
	copy(qtPayload[4:], zbuf.Bytes())

	uri := "vpn://" + base64.RawURLEncoding.EncodeToString(qtPayload)
	cfg, err := ParseInput(uri, "")
	if err != nil {
		t.Fatalf("ParseInput(vpn://) failed: %v", err)
	}
	if cfg.Name != "My Amnezia DE" || cfg.Endpoint != "198.51.100.42:44321" {
		t.Fatalf("unexpected decoded vpn:// config: %+v", cfg)
	}
}

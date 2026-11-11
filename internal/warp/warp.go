package warp

import (
	"abiroute/internal/config"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	warpAPIHost           = "api.cloudflareclient.com"
	DefaultMasquePubKeyPEM = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG\n7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==\n-----END PUBLIC KEY-----\n"
)

var warpAPIVersions = []struct {
	ver    string
	client string
	ua     string
}{
	{"v0a4471", "a-6.35-4471", "WARP for Android"},
	{"v0a2158", "a-6.10-2158", "okhttp/3.12.1"},
}

func resolveDoH(ctx context.Context, host string) []string {
	type dohTarget struct {
		ip   string
		path string
	}
	targets := []dohTarget{
		{"1.1.1.1", "/dns-query?name=" + host + "&type=A"},
		{"8.8.8.8", "/resolve?name=" + host + "&type=A"},
		{"1.0.0.1", "/dns-query?name=" + host + "&type=A"},
	}

	var out []string
	for _, t := range targets {
		tr := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 4 * time.Second}
				raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.ip, "443"))
				if err != nil {
					return nil, err
				}
				tc := tls.Client(raw, &tls.Config{ServerName: t.ip})
				if err := tc.HandshakeContext(ctx); err != nil {
					_ = raw.Close()
					return nil, err
				}
				return tc, nil
			},
		}
		cli := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+t.ip+t.path, nil)
		req.Header.Set("Accept", "application/dns-json")
		resp, err := cli.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var parsed struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if json.Unmarshal(raw, &parsed) == nil {
			for _, a := range parsed.Answer {
				if a.Type == 1 {
					if ip := net.ParseIP(a.Data); ip != nil && ip.To4() != nil {
						out = append(out, ip.To4().String())
					}
				}
			}
		}
		if len(out) > 0 {
			break
		}
	}
	return out
}

func doWarpRequest(ctx context.Context, method, path string, body any, token string) ([]byte, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	routes := []string{""} // "" = system DNS first, then DoH pinned IPs
	dohResolved := false
	var errs []string

	for _, apiSpec := range warpAPIVersions {
		for i := 0; i < len(routes); i++ {
			pinIP := routes[i]
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{ServerName: warpAPIHost},
			}
			if pinIP != "" {
				targetAddr := net.JoinHostPort(pinIP, "443")
				tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
					d := &net.Dialer{Timeout: 8 * time.Second}
					return d.DialContext(ctx, "tcp", targetAddr)
				}
			}
			cli := &http.Client{Transport: tr, Timeout: 12 * time.Second}

			var bodyReader io.Reader
			if payload != nil {
				bodyReader = bytes.NewReader(payload)
			}
			url := "https://" + warpAPIHost + "/" + apiSpec.ver + path
			req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
			if err != nil {
				return nil, err
			}
			req.Header.Set("User-Agent", apiSpec.ua)
			req.Header.Set("CF-Client-Version", apiSpec.client)
			req.Header.Set("Content-Type", "application/json; charset=UTF-8")
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			resp, err := cli.Do(req)
			if err != nil {
				errs = append(errs, err.Error())
				if !dohResolved {
					dohResolved = true
					for _, ip := range resolveDoH(ctx, warpAPIHost) {
						routes = append(routes, ip)
					}
				}
				continue
			}
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			_ = resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return raw, nil
			}
			errs = append(errs, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw))))
			if resp.StatusCode == 429 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(3 * time.Second):
				}
			}
			break
		}
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("API Cloudflare WARP недоступен")
	}
	return nil, fmt.Errorf("API Cloudflare WARP недоступен: %s", errs[len(errs)-1])
}

type cfRegResponse struct {
	Result *cfRegPayload `json:"result"`
	ID     string        `json:"id"`
	Token  string        `json:"token"`
	Config cfConfigBlock `json:"config"`
}

type cfRegPayload struct {
	ID     string        `json:"id"`
	Token  string        `json:"token"`
	Config cfConfigBlock `json:"config"`
}

type cfConfigBlock struct {
	Peers []struct {
		PublicKey string `json:"public_key"`
		Endpoint  struct {
			V4   string `json:"v4"`
			V6   string `json:"v6"`
			Host string `json:"host"`
		} `json:"endpoint"`
	} `json:"peers"`
	Interface struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
}

func unpackReg(raw []byte) (*cfRegPayload, error) {
	var top cfRegResponse
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	if top.Result != nil && top.Result.ID != "" {
		return top.Result, nil
	}
	return &cfRegPayload{
		ID:     top.ID,
		Token:  top.Token,
		Config: top.Config,
	}, nil
}

// RegisterWireGuard registers a fresh Cloudflare WARP Curve25519 profile.
func RegisterWireGuard(ctx context.Context) (*config.WarpAccount, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	serialBytes := make([]byte, 8)
	_, _ = rand.Read(serialBytes)

	body := map[string]any{
		"key":          base64.StdEncoding.EncodeToString(pub),
		"install_id":   "",
		"fcm_token":    "",
		"tos":          time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"type":         "Android",
		"model":        "PC",
		"serial_number": hex.EncodeToString(serialBytes),
		"key_type":     "curve25519",
		"tunnel_type":  "wireguard",
		"locale":       "en_US",
		"warp_enabled": true,
	}

	raw, err := doWarpRequest(ctx, http.MethodPost, "/reg", body, "")
	if err != nil {
		return nil, err
	}
	reg, err := unpackReg(raw)
	if err != nil || len(reg.Config.Peers) == 0 {
		return nil, fmt.Errorf("некорректный ответ регистрации WARP")
	}

	v4 := strings.Split(reg.Config.Interface.Addresses.V4, "/")[0]
	if v4 == "" {
		v4 = "172.16.0.2"
	}

	return &config.WarpAccount{
		PrivateKey:    base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:     base64.StdEncoding.EncodeToString(pub),
		PeerPublicKey: reg.Config.Peers[0].PublicKey,
		IPv4:          v4,
		IPv6:          strings.Split(reg.Config.Interface.Addresses.V6, "/")[0],
		DeviceID:      reg.ID,
		Token:         reg.Token,
		Created:       time.Now().Format("02.01.2006 15:04"),
		Source:        "api",
	}, nil
}

// RegisterMASQUE registers a dedicated device and enrolls an ECDSA P-256 key for MASQUE HTTP/3 & HTTP/2,
// keeping the WireGuard device untouched so protocol switching is instant.
func RegisterMASQUE(ctx context.Context) (*config.MasqueAccount, error) {
	// Step 1: Register new device
	wgTemp, err := RegisterWireGuard(ctx)
	if err != nil {
		return nil, err
	}

	// Step 2: Generate ECDSA P-256 keypair and enroll as MASQUE
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privDER, err := x509.MarshalECPrivateKey(ecPriv)
	if err != nil {
		return nil, err
	}
	pubPKIX, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	if err != nil {
		return nil, err
	}

	patchBody := map[string]any{
		"key":         base64.StdEncoding.EncodeToString(pubPKIX),
		"key_type":    "secp256r1",
		"tunnel_type": "masque",
		"name":        "ABIRoute-PC",
	}
	raw, err := doWarpRequest(ctx, http.MethodPatch, "/reg/"+wgTemp.DeviceID, patchBody, wgTemp.Token)
	if err != nil {
		return nil, fmt.Errorf("не удалось активировать ключ MASQUE: %w", err)
	}
	reg, err := unpackReg(raw)
	if err != nil {
		return nil, err
	}

	epV4 := "162.159.198.1"
	peerPEM := DefaultMasquePubKeyPEM
	if len(reg.Config.Peers) > 0 {
		if v := strings.Split(reg.Config.Peers[0].Endpoint.V4, ":")[0]; v != "" {
			epV4 = v
		}
		if pk := strings.TrimSpace(reg.Config.Peers[0].PublicKey); strings.Contains(pk, "BEGIN PUBLIC KEY") {
			peerPEM = pk
		}
	}
	v4 := strings.Split(reg.Config.Interface.Addresses.V4, "/")[0]
	if v4 == "" {
		v4 = wgTemp.IPv4
	}

	return &config.MasqueAccount{
		PrivateKeyDERB64:  base64.StdEncoding.EncodeToString(privDER),
		PublicKeyPKIXB64:  base64.StdEncoding.EncodeToString(pubPKIX),
		EndpointV4:        epV4,
		EndpointH2V4:      "162.159.198.2",
		EndpointPubKeyPEM: peerPEM,
		IPv4:              v4,
		IPv6:              strings.Split(reg.Config.Interface.Addresses.V6, "/")[0],
		DeviceID:          wgTemp.DeviceID,
		Token:             wgTemp.Token,
		Created:           time.Now().Format("02.01.2006 15:04"),
	}, nil
}

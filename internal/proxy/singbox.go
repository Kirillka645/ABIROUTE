package proxy

import (
	"abiroute/internal/config"
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const fallbackSingBoxZipURL = "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip"

func SingBoxPath() string {
	return filepath.Join(config.DataDir(), "bin", "sing-box.exe")
}

// EnsureSingBoxBinary locates or downloads the official SagerNet/sing-box Windows amd64 binary.
func EnsureSingBoxBinary(ctx context.Context, onStatus func(msg string)) (string, error) {
	dst := SingBoxPath()
	if st, err := os.Stat(dst); err == nil && st.Size() > 5_000_000 {
		return dst, nil
	}

	if onStatus != nil {
		onStatus("Загрузка официального ядра VLESS / Hysteria2 (sing-box) с GitHub…")
	}

	zipURL := resolveLatestSingBoxZip(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zipURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "ABIRoute/5.0")
	cli := &http.Client{Timeout: 90 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return "", fmt.Errorf("не удалось скачать sing-box с GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub вернул HTTP %d при загрузке sing-box", resp.StatusCode)
	}

	rawZip, err := io.ReadAll(io.LimitReader(resp.Body, 80*1024*1024))
	if err != nil {
		return "", err
	}

	zr, err := zip.NewReader(bytes.NewReader(rawZip), int64(len(rawZip)))
	if err != nil {
		return "", fmt.Errorf("повреждённый архив sing-box: %w", err)
	}

	for _, f := range zr.File {
		if strings.EqualFold(filepath.Base(f.Name), "sing-box.exe") {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			exeBytes, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				return "", err
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return "", err
			}
			tmp := dst + ".tmp"
			if err := os.WriteFile(tmp, exeBytes, 0o755); err != nil {
				return "", err
			}
			if err := os.Rename(tmp, dst); err != nil {
				return "", err
			}
			return dst, nil
		}
	}
	return "", fmt.Errorf("в архиве не найден sing-box.exe")
}

func resolveLatestSingBoxZip(ctx context.Context) string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, "https://api.github.com/repos/SagerNet/sing-box/releases/latest", nil)
	req.Header.Set("User-Agent", "ABIRoute/5.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fallbackSingBoxZipURL
	}
	defer resp.Body.Close()
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if json.NewDecoder(resp.Body).Decode(&rel) == nil {
		for _, a := range rel.Assets {
			if strings.HasSuffix(a.Name, "-windows-amd64.zip") && !strings.Contains(a.Name, "legacy") {
				return a.URL
			}
		}
	}
	return fallbackSingBoxZipURL
}

// BuildSingBoxConfig generates a modern sing-box v1.12+ JSON configuration with Wintun inbound (auto_route=false)
// and physical NIC outbound binding so split-tunnel routes never loop.
func BuildSingBoxConfig(parsed *ParsedOutbound, ifaceName string, mtu int, bindPhysIP string, clashPort int) ([]byte, error) {
	if mtu < 1200 {
		mtu = 1280
	}

	outbound, err := buildOutboundMap(parsed, bindPhysIP)
	if err != nil {
		return nil, err
	}

	directOut := map[string]any{
		"type": "direct",
		"tag":  "direct",
	}
	if bindPhysIP != "" {
		directOut["inet4_bind_address"] = bindPhysIP
	}

	cfg := map[string]any{
		"log": map[string]any{
			"level": "warn",
		},
		"dns": map[string]any{
			"servers": []map[string]any{
				{
					"type":   "https",
					"tag":    "dns-remote",
					"server": "1.1.1.1",
					"detour": "proxy",
				},
				{
					"type":   "udp",
					"tag":    "dns-direct",
					"server": "1.1.1.1",
				},
			},
			"final": "dns-direct",
		},
		"inbounds": []map[string]any{
			{
				"type":           "tun",
				"tag":            "tun-in",
				"interface_name": ifaceName,
				"address":        []string{"172.19.0.1/30"},
				"mtu":            mtu,
				"auto_route":     false,
				"strict_route":   false,
				"stack":          "gvisor",
			},
		},
		"outbounds": []map[string]any{
			outbound,
			directOut,
		},
		"route": map[string]any{
			"final":                   "proxy",
			"default_domain_resolver": "dns-direct",
		},
	}

	if clashPort > 0 {
		cfg["experimental"] = map[string]any{
			"clash_api": map[string]any{
				"external_controller": fmt.Sprintf("127.0.0.1:%d", clashPort),
			},
		}
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func buildOutboundMap(p *ParsedOutbound, bindPhysIP string) (map[string]any, error) {
	m := map[string]any{
		"tag":         "proxy",
		"server":      p.Node.Server,
		"server_port": p.Node.Port,
	}
	if bindPhysIP != "" {
		m["inet4_bind_address"] = bindPhysIP
	}

	switch p.Node.Scheme {
	case "vless":
		m["type"] = "vless"
		m["uuid"] = p.UUID
		m["packet_encoding"] = "xudp"
		if p.Flow != "" {
			m["flow"] = p.Flow
		}
		if p.Security == "tls" || p.Security == "reality" {
			tlsObj := map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(p.SNI, p.Node.Server),
				"insecure":    p.Insecure,
				"utls": map[string]any{
					"enabled":     true,
					"fingerprint": firstNonEmpty(p.FP, "chrome"),
				},
			}
			if len(p.ALPN) > 0 {
				tlsObj["alpn"] = p.ALPN
			}
			if p.Security == "reality" {
				tlsObj["reality"] = map[string]any{
					"enabled":    true,
					"public_key": p.PublicKey,
					"short_id":   p.ShortID,
				}
			}
			m["tls"] = tlsObj
		}
		applyTransport(m, p)

	case "hysteria2":
		m["type"] = "hysteria2"
		m["password"] = p.Password
		if p.UpMbps > 0 {
			m["up_mbps"] = p.UpMbps
		}
		if p.DownMbps > 0 {
			m["down_mbps"] = p.DownMbps
		}
		if strings.EqualFold(p.ObfsType, "salamander") && p.ObfsPass != "" {
			m["obfs"] = map[string]any{
				"type":     "salamander",
				"password": p.ObfsPass,
			}
		}
		m["tls"] = map[string]any{
			"enabled":     true,
			"server_name": firstNonEmpty(p.SNI, p.Node.Server),
			"insecure":    p.Insecure,
		}

	case "trojan":
		m["type"] = "trojan"
		m["password"] = p.Password
		m["tls"] = map[string]any{
			"enabled":     true,
			"server_name": firstNonEmpty(p.SNI, p.Node.Server),
			"insecure":    p.Insecure,
			"utls": map[string]any{
				"enabled":     true,
				"fingerprint": firstNonEmpty(p.FP, "chrome"),
			},
		}
		applyTransport(m, p)

	case "ss":
		m["type"] = "shadowsocks"
		m["method"] = p.Method
		m["password"] = p.Password

	case "socks5":
		m["type"] = "socks"
		m["version"] = "5"
		if p.UUID != "" {
			m["username"] = p.UUID
			m["password"] = p.Password
		}

	default:
		return nil, fmt.Errorf("unsupported proxy scheme %s", p.Node.Scheme)
	}

	return m, nil
}

func applyTransport(m map[string]any, p *ParsedOutbound) {
	switch p.Transport {
	case "ws":
		tr := map[string]any{"type": "ws"}
		if p.Path != "" {
			tr["path"] = p.Path
		}
		if p.HostHeader != "" {
			tr["headers"] = map[string]string{"Host": p.HostHeader}
		}
		m["transport"] = tr
	case "grpc":
		tr := map[string]any{"type": "grpc"}
		if p.ServiceName != "" {
			tr["service_name"] = p.ServiceName
		}
		m["transport"] = tr
	case "httpupgrade":
		tr := map[string]any{"type": "httpupgrade"}
		if p.Path != "" {
			tr["path"] = p.Path
		}
		if p.HostHeader != "" {
			tr["host"] = p.HostHeader
		}
		m["transport"] = tr
	}
}

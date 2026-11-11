package obf

import (
	"abiroute/internal/config"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ParseInput accepts either a .conf text OR an Amnezia vpn://... URI and returns a CustomTunnelConfig.
func ParseInput(input, fallbackName string) (*config.CustomTunnelConfig, error) {
	trimmed := strings.TrimSpace(input)
	if strings.HasPrefix(strings.ToLower(trimmed), "vpn://") {
		return ParseVPNURI(trimmed)
	}
	return ParseConf(trimmed, fallbackName)
}

// ParseVPNURI decodes an AmneziaVPN vpn:// share link (base64url of 4-byte Qt qCompress header + zlib JSON).
func ParseVPNURI(uri string) (*config.CustomTunnelConfig, error) {
	b64 := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(uri, "vpn://"), "VPN://"))
	b64 = strings.TrimRight(b64, "=")

	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		// Fallback to standard base64 without padding
		raw, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("не удалось декодировать ссылку vpn://: %w", err)
		}
	}

	var jsonBytes []byte
	if len(raw) > 4 && (raw[4] == 0x78) {
		// Qt qCompress prepends 4-byte big-endian uncompressed length before zlib stream
		zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
		if err != nil {
			return nil, fmt.Errorf("ошибка распаковки контейнера vpn://: %w", err)
		}
		defer zr.Close()
		jsonBytes, err = io.ReadAll(io.LimitReader(zr, 2*1024*1024))
		if err != nil {
			return nil, fmt.Errorf("ошибка чтения контейнера vpn://: %w", err)
		}
	} else if len(raw) > 0 && raw[0] == '{' {
		jsonBytes = raw
	} else {
		return nil, fmt.Errorf("неизвестный формат контейнера vpn://")
	}

	var root struct {
		Description string `json:"description"`
		HostName    string `json:"hostName"`
		Containers  []struct {
			Container string          `json:"container"`
			Awg       json.RawMessage `json:"awg"`
			Wireguard json.RawMessage `json:"wireguard"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(jsonBytes, &root); err != nil {
		return nil, fmt.Errorf("не удалось разобрать JSON из vpn://: %w", err)
	}

	for _, c := range root.Containers {
		for _, blob := range []json.RawMessage{c.Awg, c.Wireguard} {
			if len(blob) == 0 {
				continue
			}
			var inner struct {
				LastConfig string `json:"last_config"`
			}
			if err := json.Unmarshal(blob, &inner); err == nil && inner.LastConfig != "" {
				// last_config can itself be JSON with "config" field or direct .conf text
				var lc struct {
					Config string `json:"config"`
				}
				confText := inner.LastConfig
				if json.Unmarshal([]byte(inner.LastConfig), &lc) == nil && lc.Config != "" {
					confText = lc.Config
				}
				name := root.Description
				if name == "" && root.HostName != "" {
					name = "Amnezia " + root.HostName
				}
				return ParseConf(confText, name)
			}
		}
	}

	return nil, fmt.Errorf("в ссылке vpn:// не найден профиль AmneziaWG или WireGuard")
}

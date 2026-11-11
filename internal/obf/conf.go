package obf

import (
	"abiroute/internal/config"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const WarpDefaultPeerPubKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

func PubFromPrivB64(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("некорректный PrivateKey WireGuard (нужен base64 32 байта)")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// ParseConf parses a WireGuard or AmneziaWG .conf text into a CustomTunnelConfig.
func ParseConf(text, name string) (*config.CustomTunnelConfig, error) {
	text = strings.TrimPrefix(strings.ReplaceAll(text, "\r\n", "\n"), "\ufeff")
	section := ""
	peerCount := 0
	iface := map[string]string{}
	peer := map[string]string{}

	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				peerCount++
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if idx := strings.IndexByte(v, '#'); idx >= 0 {
			v = v[:idx]
		}
		v = strings.TrimSpace(v)
		switch {
		case section == "interface":
			iface[k] = v
		case section == "peer" && peerCount == 1:
			peer[k] = v
		}
	}

	priv := iface["privatekey"]
	if priv == "" {
		return nil, fmt.Errorf("в конфиге отсутствует PrivateKey")
	}
	pub, err := PubFromPrivB64(priv)
	if err != nil {
		return nil, err
	}

	peerPub := peer["publickey"]
	if rawPeer, err := base64.StdEncoding.DecodeString(peerPub); err != nil || len(rawPeer) != 32 {
		return nil, fmt.Errorf("в секции [Peer] отсутствует корректный PublicKey")
	}

	var addrV4 string
	for _, part := range strings.FieldsFunc(iface["address"], func(r rune) bool { return r == ',' || r == ' ' }) {
		ipStr := strings.Split(strings.TrimSpace(part), "/")[0]
		if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
			addrV4 = ip.To4().String()
			break
		}
	}
	if addrV4 == "" {
		addrV4 = "172.16.0.2"
	}

	ep := peer["endpoint"]
	if ep == "" {
		if peerPub == WarpDefaultPeerPubKey {
			ep = "162.159.192.1:2408"
		} else {
			return nil, fmt.Errorf("в конфиге своего сервера отсутствует Endpoint")
		}
	}

	mtu, _ := strconv.Atoi(iface["mtu"])
	if mtu < 1200 || mtu > 1500 {
		mtu = 1280
	}
	jc, _ := strconv.Atoi(iface["jc"])
	jmin, _ := strconv.Atoi(iface["jmin"])
	jmax, _ := strconv.Atoi(iface["jmax"])

	sMap := map[string]int{}
	for _, sk := range []string{"s1", "s2", "s3", "s4"} {
		if sv, ok := iface[sk]; ok {
			if n, err := strconv.Atoi(sv); err == nil {
				sMap[strings.ToUpper(sk)] = n
			}
		}
	}
	hMap := map[string]string{}
	for _, hk := range []string{"h1", "h2", "h3", "h4"} {
		if hv := iface[hk]; hv != "" {
			hMap[strings.ToUpper(hk)] = hv
		}
	}
	iMap := map[string]string{}
	for _, ik := range []string{"i1", "i2", "i3", "i4", "i5"} {
		if iv := iface[ik]; iv != "" {
			iMap[strings.ToUpper(ik)] = iv
		}
	}

	if strings.TrimSpace(name) == "" {
		if peerPub == WarpDefaultPeerPubKey {
			name = "Импортированный WARP"
		} else {
			name = "Свой сервер " + ep
		}
	}

	return &config.CustomTunnelConfig{
		Name:          name,
		PrivateKey:    priv,
		PublicKey:     pub,
		PeerPublicKey: peerPub,
		PresharedKey:  peer["presharedkey"],
		AddressV4:     addrV4,
		Endpoint:      ep,
		MTU:           mtu,
		Jc:            jc,
		Jmin:          jmin,
		Jmax:          jmax,
		S:             sMap,
		H:             hMap,
		I:             iMap,
		Created:       time.Now().Format("02.01.2006 15:04"),
	}, nil
}

// BuildConf renders an AmneziaWG / WireGuard .conf file with split-tunnel AllowedIPs.
func BuildConf(privKey, addrV4, peerPubKey, psk, endpoint string, mtu int, prof Profile, allowedRanges []string) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privKey)
	fmt.Fprintf(&b, "Address = %s/32\n", addrV4)
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	if prof.Jc > 0 {
		fmt.Fprintf(&b, "Jc = %d\nJmin = %d\nJmax = %d\n", prof.Jc, prof.Jmin, prof.Jmax)
	}
	fmt.Fprintf(&b, "S1 = %d\nS2 = %d\n", prof.S1, prof.S2)
	h1, h2, h3, h4 := prof.H1, prof.H2, prof.H3, prof.H4
	if h1 == "" {
		h1, h2, h3, h4 = "1", "2", "3", "4"
	}
	fmt.Fprintf(&b, "H1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n", h1, h2, h3, h4)
	for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
		if v := prof.I[k]; v != "" {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", peerPubKey)
	if psk != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowedRanges, ", "))
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

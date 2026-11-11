package proxy

import (
	"abiroute/internal/config"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ParsedOutbound struct {
	Node       config.ProxyNode
	UUID       string
	Password   string
	Method     string
	Flow       string
	Security   string // "none" | "tls" | "reality"
	SNI        string
	ALPN       []string
	FP         string
	PublicKey  string // Reality pbk
	ShortID    string // Reality sid
	Transport  string // "tcp" | "ws" | "grpc" | "httpupgrade"
	Path       string
	HostHeader string
	ServiceName string
	ObfsType   string // Hysteria2 "salamander"
	ObfsPass   string
	Insecure   bool
	UpMbps     int
	DownMbps   int
}

func makeID(raw string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(raw)))
	return "px-" + hex.EncodeToString(sum[:6])
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// ParseURI parses vless://, hy2://, hysteria2://, trojan://, ss://, and socks5:// links.
func ParseURI(raw string, subURL string) (*ParsedOutbound, error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, fmt.Errorf("пустая ссылка")
	}

	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("некорректный URI: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "hy2":
		scheme = "hysteria2"
	case "socks":
		scheme = "socks5"
	}

	switch scheme {
	case "vless", "hysteria2", "trojan", "ss", "socks5":
	default:
		return nil, fmt.Errorf("неподдерживаемая схема %q (поддерживаются vless://, hy2://, trojan://, ss://, socks5://)", u.Scheme)
	}

	// Handle ss://BASE64@host:port or ss://BASE64#tag
	var ssMethod, ssPass string
	if scheme == "ss" {
		if u.Host == "" && u.Opaque != "" {
			decoded, err := decodeBase64Flexible(u.Opaque)
			if err != nil {
				return nil, fmt.Errorf("не удалось декодировать ss:// ссылку")
			}
			rebuilt := "ss://" + string(decoded)
			if u.Fragment != "" {
				rebuilt += "#" + u.Fragment
			}
			u, err = url.Parse(rebuilt)
			if err != nil {
				return nil, err
			}
		}
		if u.User != nil {
			userStr := u.User.String()
			if p, ok := u.User.Password(); ok {
				ssMethod = u.User.Username()
				ssPass = p
			} else if decoded, err := decodeBase64Flexible(userStr); err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					ssMethod, ssPass = parts[0], parts[1]
				}
			}
		}
		if ssMethod == "" || ssPass == "" {
			return nil, fmt.Errorf("в ss:// ссылке не найден шифр или пароль")
		}
	}

	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		if scheme == "hysteria2" || scheme == "vless" || scheme == "trojan" {
			portStr = "443"
		} else {
			portStr = "1080"
		}
	}
	// Hysteria2 port hopping "443,20000-30000" -> take primary port
	if idx := strings.IndexAny(portStr, ",-"); idx > 0 {
		portStr = portStr[:idx]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || host == "" || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("некорректный хост или порт в %s://", scheme)
	}

	name, _ := url.QueryUnescape(u.Fragment)
	name = strings.TrimSpace(name)
	if name == "" {
		name = fmt.Sprintf("%s %s:%d", strings.ToUpper(scheme), host, port)
	}

	q := u.Query()
	out := &ParsedOutbound{
		Node: config.ProxyNode{
			ID:      makeID(line),
			Name:    name,
			Scheme:  scheme,
			Server:  host,
			Port:    port,
			RawURI:  line,
			SubURL:  subURL,
			Created: time.Now().Format("02.01.2006 15:04"),
		},
		Method:    ssMethod,
		Password:  ssPass,
		Flow:      q.Get("flow"),
		Security:  strings.ToLower(q.Get("security")),
		SNI:       firstNonEmpty(q.Get("sni"), q.Get("peer")),
		FP:        firstNonEmpty(q.Get("fp"), "chrome"),
		PublicKey: q.Get("pbk"),
		ShortID:   q.Get("sid"),
		Transport: strings.ToLower(firstNonEmpty(q.Get("type"), "tcp")),
		Path:      q.Get("path"),
		HostHeader: q.Get("host"),
		ServiceName: q.Get("serviceName"),
		ObfsType:  q.Get("obfs"),
		ObfsPass:  q.Get("obfs-password"),
		Insecure:  q.Get("insecure") == "1" || strings.EqualFold(q.Get("insecure"), "true") || q.Get("allowInsecure") == "1",
	}
	if alpn := q.Get("alpn"); alpn != "" {
		for _, a := range strings.Split(alpn, ",") {
			if strings.TrimSpace(a) != "" {
				out.ALPN = append(out.ALPN, strings.TrimSpace(a))
			}
		}
	}
	out.UpMbps, _ = strconv.Atoi(q.Get("upmbps"))
	out.DownMbps, _ = strconv.Atoi(q.Get("downmbps"))

	if u.User != nil {
		switch scheme {
		case "vless":
			out.UUID = u.User.Username()
			if out.UUID == "" {
				return nil, fmt.Errorf("в vless:// отсутствует UUID")
			}
		case "trojan", "hysteria2":
			if pw, ok := u.User.Password(); ok && u.User.Username() != "" {
				out.Password = u.User.Username() + ":" + pw
			} else {
				out.Password = u.User.Username()
			}
		case "socks5":
			out.UUID = u.User.Username()
			out.Password, _ = u.User.Password()
		}
	}

	return out, nil
}

// ParseBatch parses multi-line or base64-encoded lists of proxy URIs.
func ParseBatch(text, subURL string) ([]config.ProxyNode, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, fmt.Errorf("пустой текст")
	}

	// If no "://" visible directly, try base64 subscription decoding
	if !strings.Contains(trimmed, "://") {
		if decoded, err := decodeBase64Flexible(trimmed); err == nil {
			trimmed = string(decoded)
		}
	}

	var nodes []config.ProxyNode
	seen := map[string]bool{}
	for _, rawLine := range strings.Split(strings.ReplaceAll(trimmed, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if p, err := ParseURI(line, subURL); err == nil && !seen[p.Node.ID] {
			seen[p.Node.ID] = true
			nodes = append(nodes, p.Node)
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("не найдено ни одной поддерживаемой ссылки (vless://, hy2://, trojan://, ss://, socks5://)")
	}
	return nodes, nil
}

// FetchSubscription downloads a subscription URL (Happ / v2rayN / Marzban / 3x-ui) and extracts all proxy nodes.
func FetchSubscription(ctx context.Context, subURL string) ([]config.ProxyNode, error) {
	subURL = strings.TrimSpace(subURL)
	if !strings.HasPrefix(subURL, "http://") && !strings.HasPrefix(subURL, "https://") {
		return nil, fmt.Errorf("ссылка подписки должна начинаться с https://")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "v2rayNG/1.9.5 ABI-Route/5.0")
	cli := &http.Client{Timeout: 15 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить подписку: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("сервер подписки вернул HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	return ParseBatch(string(raw), subURL)
}

// MeasureNodeTCPPing measures quick TCP/UDP reachability RTT to the proxy host.
func MeasureNodeTCPPing(host string, port int, bindIP string) int {
	d := net.Dialer{Timeout: 1800 * time.Millisecond}
	if bindIP != "" {
		if sip := net.ParseIP(bindIP).To4(); sip != nil {
			d.LocalAddr = &net.TCPAddr{IP: sip, Port: 0}
		}
	}
	t0 := time.Now()
	c, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		_ = c.Close()
		return int(time.Since(t0).Milliseconds())
	}
	// Hysteria2 servers sometimes only open UDP 443; resolve DNS + fast ICMP/UDP fallback
	t1 := time.Now()
	uc, uerr := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), 1200*time.Millisecond)
	if uerr == nil {
		_ = uc.Close()
		ms := int(time.Since(t1).Milliseconds())
		if ms < 1 {
			ms = 1
		}
		return ms
	}
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

package tunnel

import (
	"abiroute/internal/config"
	"abiroute/internal/netwin"
	"abiroute/internal/warp"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

const (
	masqueConnectSNI = "consumer-masque.cloudflareclient.com"
	masqueConnectURI = "https://cloudflareaccess.com"
	masqueHeadroom   = 1
)

type MASQUEConfig struct {
	Account  *config.MasqueAccount
	UseHTTP2 bool
	MTU      int
	Routes   []string
	PhysNIC  *netwin.PhysicalNIC
}

type MASQUETunnel struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	tunDev     tun.Device
	ifaceName  string
	endpointIP string
	physNIC    *netwin.PhysicalNIC
	applied    []string

	rxBytes       atomic.Uint64
	txBytes       atomic.Uint64
	lastConnectTS atomic.Int64
}

func prepareMASQUETLS(acct *config.MasqueAccount, nextProto string) (*tls.Config, error) {
	privDER, err := base64.StdEncoding.DecodeString(acct.PrivateKeyDERB64)
	if err != nil {
		return nil, fmt.Errorf("некорректный ключ MASQUE: %w", err)
	}
	privKey, err := x509.ParseECPrivateKey(privDER)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{}, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	pemBytes := []byte(acct.EndpointPubKeyPEM)
	if len(pemBytes) == 0 {
		pemBytes = []byte(warp.DefaultMasquePubKeyPEM)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("не удалось прочитать публичный ключ узла MASQUE")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	peerPub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("неподдерживаемый тип ключа узла MASQUE")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certDER},
				PrivateKey:  privKey,
			},
		},
		ServerName:         masqueConnectSNI,
		NextProtos:         []string{nextProto},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("empty server certificate")
			}
			c, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			epKey, ok := c.PublicKey.(*ecdsa.PublicKey)
			if !ok || !epKey.Equal(peerPub) {
				return errors.New("несовпадение отпечатка ключа сервера MASQUE")
			}
			return nil
		},
	}, nil
}

func dialMASQUEConn(ctx context.Context, acct *config.MasqueAccount, useHTTP2 bool, bindLocalIP string) (*net.UDPConn, *http3.Transport, *connectip.Conn, error) {
	tmpl := uritemplate.MustNew(masqueConnectURI)
	hdrs := http.Header{"User-Agent": []string{""}}

	if useHTTP2 {
		epIP := acct.EndpointH2V4
		if epIP == "" {
			epIP = "162.159.198.2"
		}
		tlsCfg, err := prepareMASQUETLS(acct, "h2")
		if err != nil {
			return nil, nil, nil, err
		}
		hdrs.Set("cf-connect-proto", "cf-connect-ip")
		hdrs.Set("pq-enabled", "false")
		target := net.JoinHostPort(epIP, "443")

		h2Tr := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				d := &net.Dialer{Timeout: 6 * time.Second}
				if bindLocalIP != "" {
					if sip := net.ParseIP(bindLocalIP).To4(); sip != nil {
						d.LocalAddr = &net.TCPAddr{IP: sip, Port: 0}
					}
				}
				rawConn, err := d.DialContext(ctx, "tcp4", target)
				if err != nil {
					return nil, err
				}
				tc := tls.Client(rawConn, tlsCfg)
				if err := tc.HandshakeContext(ctx); err != nil {
					_ = rawConn.Close()
					return nil, err
				}
				return tc, nil
			},
		}
		cli := &http.Client{Transport: h2Tr}
		ipConn, rsp, err := connectip.DialH2(ctx, cli, tmpl, hdrs)
		if err != nil {
			return nil, nil, nil, err
		}
		if rsp.StatusCode != 200 {
			_ = ipConn.Close()
			return nil, nil, nil, fmt.Errorf("MASQUE HTTP/2 status %d", rsp.StatusCode)
		}
		return nil, nil, ipConn, nil
	}

	epIP := acct.EndpointV4
	if epIP == "" {
		epIP = "162.159.198.1"
	}
	tlsCfg, err := prepareMASQUETLS(acct, http3.NextProtoH3)
	if err != nil {
		return nil, nil, nil, err
	}

	var laddr *net.UDPAddr
	if bindLocalIP != "" {
		if sip := net.ParseIP(bindLocalIP).To4(); sip != nil {
			laddr = &net.UDPAddr{IP: sip, Port: 0}
		}
	}
	udpConn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, nil, nil, err
	}

	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	qCfg := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 20 * time.Second,
	}
	remoteUDP := &net.UDPAddr{IP: net.ParseIP(epIP).To4(), Port: 443}
	qConn, err := qtr.Dial(ctx, remoteUDP, tlsCfg, qCfg)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, nil, err
	}

	h3Tr := &http3.Transport{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{0x276: 1},
		DisableCompression: true,
	}
	hConn := h3Tr.NewClientConn(qConn)
	ipConn, rsp, err := connectip.Dial(ctx, hConn, tmpl, "cf-connect-ip", hdrs, true)
	if err != nil {
		_ = h3Tr.Close()
		_ = qConn.CloseWithError(0, "dial failed")
		_ = udpConn.Close()
		return nil, nil, nil, err
	}
	if rsp.StatusCode != 200 {
		_ = ipConn.Close()
		_ = h3Tr.Close()
		_ = udpConn.Close()
		return nil, nil, nil, fmt.Errorf("MASQUE HTTP/3 status %d", rsp.StatusCode)
	}
	return udpConn, h3Tr, ipConn, nil
}

// ProbeMASQUE verifies whether Cloudflare MASQUE (HTTP/3 or HTTP/2) connects and passes DPI, returning RTT in ms.
func ProbeMASQUE(ctx context.Context, acct *config.MasqueAccount, useHTTP2 bool, bindLocalIP string) (int, error) {
	if acct == nil || acct.PrivateKeyDERB64 == "" {
		return 0, fmt.Errorf("MASQUE account not enrolled")
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	t0 := time.Now()
	udpConn, h3Tr, ipConn, err := dialMASQUEConn(dctx, acct, useHTTP2, bindLocalIP)
	if err != nil {
		return 0, err
	}
	rtt := int(time.Since(t0).Milliseconds())
	_ = ipConn.Close()
	if h3Tr != nil {
		_ = h3Tr.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
	return rtt, nil
}

func StartMASQUE(cfg MASQUEConfig) (*MASQUETunnel, error) {
	if cfg.Account == nil || cfg.Account.PrivateKeyDERB64 == "" {
		return nil, fmt.Errorf("профиль MASQUE не зарегистрирован")
	}
	if err := EnsureWintunDLL(); err != nil {
		return nil, fmt.Errorf("не удалось подготовить драйвер Wintun: %w", err)
	}

	epIP := cfg.Account.EndpointV4
	if cfg.UseHTTP2 {
		epIP = cfg.Account.EndpointH2V4
		if epIP == "" {
			epIP = "162.159.198.2"
		}
	} else if epIP == "" {
		epIP = "162.159.198.1"
	}

	mtu := cfg.MTU
	if mtu < 1200 || mtu > 1380 {
		mtu = 1280
	}

	// Verify connection before creating routes so failures fail fast cleanly
	bindIP := ""
	if cfg.PhysNIC != nil {
		bindIP = cfg.PhysNIC.IP
	}
	initCtx, initCancel := context.WithTimeout(context.Background(), 8*time.Second)
	udpConn, h3Tr, ipConn, err := dialMASQUEConn(initCtx, cfg.Account, cfg.UseHTTP2, bindIP)
	initCancel()
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к серверу MASQUE: %w", err)
	}

	tunDev, err := tun.CreateTUN(InterfaceName, mtu)
	if err != nil {
		_ = ipConn.Close()
		if h3Tr != nil {
			_ = h3Tr.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}
		return nil, fmt.Errorf("не удалось создать адаптер Wintun: %w", err)
	}
	ifaceName, err := tunDev.Name()
	if err != nil || ifaceName == "" {
		ifaceName = InterfaceName
	}

	cleanRoutes := netwin.NormalizePrefixes(cfg.Routes, epIP)
	if err := netwin.ConfigureTunInterface(ifaceName, cfg.Account.IPv4, mtu); err != nil {
		_ = tunDev.Close()
		_ = ipConn.Close()
		return nil, err
	}
	if err := netwin.SyncRoutes(ifaceName, epIP, cfg.PhysNIC, cleanRoutes, nil); err != nil {
		_ = tunDev.Close()
		_ = ipConn.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	mt := &MASQUETunnel{
		ctx:        ctx,
		cancel:     cancel,
		tunDev:     tunDev,
		ifaceName:  ifaceName,
		endpointIP: epIP,
		physNIC:    cfg.PhysNIC,
		applied:    cleanRoutes,
	}
	mt.lastConnectTS.Store(time.Now().Unix())

	go mt.supervise(cfg.Account, cfg.UseHTTP2, mtu, bindIP, udpConn, h3Tr, ipConn)
	return mt, nil
}

func (m *MASQUETunnel) supervise(acct *config.MasqueAccount, useH2 bool, mtu int, bindIP string, initUDP *net.UDPConn, initH3 *http3.Transport, initIP *connectip.Conn) {
	udpConn, h3Tr, ipConn := initUDP, initH3, initIP
	var readMu sync.Mutex

	for {
		if m.ctx.Err() != nil {
			return
		}
		if ipConn == nil {
			dctx, dcancel := context.WithTimeout(m.ctx, 8*time.Second)
			var err error
			udpConn, h3Tr, ipConn, err = dialMASQUEConn(dctx, acct, useH2, bindIP)
			dcancel()
			if err != nil {
				select {
				case <-m.ctx.Done():
					return
				case <-time.After(2 * time.Second):
					continue
				}
			}
			m.lastConnectTS.Store(time.Now().Unix())
		}

		errCh := make(chan error, 2)
		activeIP := ipConn

		// TUN -> MASQUE outbound pump
		go func() {
			rawBuf := make([]byte, mtu+masqueHeadroom+128)
			bufs := [][]byte{nil}
			sizes := []int{0}
			for {
				if m.ctx.Err() != nil {
					return
				}
				readMu.Lock()
				bufs[0] = rawBuf[masqueHeadroom:]
				sizes[0] = 0
				_, err := m.tunDev.Read(bufs, sizes, 0)
				n := sizes[0]
				readMu.Unlock()
				if err != nil {
					errCh <- err
					return
				}
				if n <= 0 {
					continue
				}
				m.txBytes.Add(uint64(n))
				icmpReply, err := activeIP.WritePacketBuffer(rawBuf, masqueHeadroom, n)
				if err != nil {
					var ce *connectip.CloseError
					if errors.As(err, &ce) {
						errCh <- err
						return
					}
					continue
				}
				if len(icmpReply) > 0 {
					out := [][]byte{icmpReply}
					_, _ = m.tunDev.Write(out, 0)
				}
			}
		}()

		// MASQUE -> TUN inbound pump
		go func() {
			out := [][]byte{nil}
			for {
				pkt, err := activeIP.ReadPacketZeroCopy(true)
				if err != nil {
					var ce *connectip.CloseError
					if useH2 || errors.As(err, &ce) || m.ctx.Err() != nil {
						errCh <- err
						return
					}
					continue
				}
				if len(pkt) == 0 {
					continue
				}
				m.rxBytes.Add(uint64(len(pkt)))
				out[0] = pkt
				if _, err := m.tunDev.Write(out, 0); err != nil {
					errCh <- err
					return
				}
			}
		}()

		select {
		case <-m.ctx.Done():
		case <-errCh:
		}

		_ = activeIP.Close()
		if h3Tr != nil {
			_ = h3Tr.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}
		ipConn, h3Tr, udpConn = nil, nil, nil

		if m.ctx.Err() != nil {
			return
		}
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(1500 * time.Millisecond):
		}
	}
}

func (m *MASQUETunnel) UpdateRoutes(desiredPrefixes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clean := netwin.NormalizePrefixes(desiredPrefixes, m.endpointIP)
	if err := netwin.SyncRoutes(m.ifaceName, m.endpointIP, m.physNIC, clean, m.applied); err != nil {
		return err
	}
	m.applied = clean
	return nil
}

func (m *MASQUETunnel) AppliedRoutes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]string, len(m.applied))
	copy(cp, m.applied)
	return cp
}

func (m *MASQUETunnel) Stats() Stats {
	ts := m.lastConnectTS.Load()
	return Stats{
		RxBytes:          m.rxBytes.Load(),
		TxBytes:          m.txBytes.Load(),
		LastHandshakeSec: ts,
		Connected:        ts > 0,
	}
}

func (m *MASQUETunnel) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
	netwin.CleanupRoutes(m.ifaceName, m.endpointIP, m.applied)
	if m.tunDev != nil {
		_ = m.tunDev.Close()
		m.tunDev = nil
	}
	return nil
}

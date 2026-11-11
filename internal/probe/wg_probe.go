package probe

import (
	"abiroute/internal/config"
	"abiroute/internal/obf"
	"abiroute/internal/warp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

var (
	wgConstruction = []byte("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
	wgIdentifier   = []byte("WireGuard v1 zx2c4 Jason@zx2c4.com")
	wgLabelMac1    = []byte("mac1----")
	taiLastNano    atomic.Int64
)

var warpScanIPs = []string{
	"162.159.192.1", "162.159.192.2", "162.159.192.5", "162.159.192.7", "162.159.192.9", "162.159.192.10",
	"162.159.193.1", "162.159.193.3", "162.159.193.5", "162.159.193.10",
	"162.159.195.1", "162.159.195.4", "162.159.195.8",
	"188.114.96.1", "188.114.96.3", "188.114.97.1", "188.114.97.4", "188.114.98.1", "188.114.99.1",
}

var warpScanPorts = []int{
	2408, 500, 1701, 4500, 878, 894, 854, 939, 7559,
	859, 864, 880, 890, 908, 928, 942, 968, 987, 1070, 1180, 2371, 3476, 4177,
}

func b2Hash(parts ...[]byte) []byte {
	h, _ := blake2s.New256(nil)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func b2HMAC(key, data []byte) []byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func b2KDF(key, data []byte, n int) [][]byte {
	t0 := b2HMAC(key, data)
	out := make([][]byte, 0, n)
	var prev []byte
	for i := byte(1); int(i) <= n; i++ {
		buf := make([]byte, len(prev)+1)
		copy(buf, prev)
		buf[len(prev)] = i
		prev = b2HMAC(t0, buf)
		out = append(out, prev)
	}
	return out
}

func wgNonce(counter uint64) []byte {
	var n [12]byte
	binary.LittleEndian.PutUint64(n[4:], counter)
	return n[:]
}

func tai64nNow() []byte {
	now := time.Now().UnixNano()
	for {
		prev := taiLastNano.Load()
		next := now
		if next <= prev {
			next = prev + 1
		}
		if taiLastNano.CompareAndSwap(prev, next) {
			now = next
			break
		}
	}
	sec := uint64(now / 1_000_000_000)
	nsec := uint32(now % 1_000_000_000)
	var b [12]byte
	binary.BigEndian.PutUint64(b[0:8], 0x400000000000000a+sec)
	binary.BigEndian.PutUint32(b[8:12], nsec)
	return b[:]
}

// ProbeSession is an ephemeral userspace WireGuard/AmneziaWG client for honest in-tunnel ICMP & DNS checks.
type ProbeSession struct {
	sPriv   []byte
	sPub    []byte
	rPub    []byte
	psk     []byte
	srcIP   net.IP
	conn    *net.UDPConn
	addr    *net.UDPAddr
	obfProf obf.Profile

	cState  []byte
	hState  []byte
	ePriv   []byte
	selfIdx uint32
	peerIdx uint32
	kSend   []byte
	kRecv   []byte
	counter uint64
}

func NewProbeSession(privB64, peerPubB64, pskB64, innerIPv4, endpoint string, prof obf.Profile, bindLocalIP string) (*ProbeSession, error) {
	sPriv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil || len(sPriv) != 32 {
		return nil, fmt.Errorf("invalid private key")
	}
	sPub, err := curve25519.X25519(sPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	rPub, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil || len(rPub) != 32 {
		return nil, fmt.Errorf("invalid peer public key")
	}
	var psk []byte
	if pskB64 != "" {
		psk, _ = base64.StdEncoding.DecodeString(pskB64)
	}
	if len(psk) != 32 {
		psk = make([]byte, 32)
	}

	udpAddr, err := net.ResolveUDPAddr("udp4", endpoint)
	if err != nil {
		return nil, err
	}

	var laddr *net.UDPAddr
	if bindLocalIP != "" {
		if ip := net.ParseIP(bindLocalIP); ip != nil && ip.To4() != nil {
			laddr = &net.UDPAddr{IP: ip.To4(), Port: 0}
		}
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, err
	}

	src := net.ParseIP(innerIPv4).To4()
	if src == nil {
		src = net.IPv4(172, 16, 0, 2).To4()
	}

	return &ProbeSession{
		sPriv:   sPriv,
		sPub:    sPub,
		rPub:    rPub,
		psk:     psk,
		srcIP:   src,
		conn:    conn,
		addr:    udpAddr,
		obfProf: prof,
	}, nil
}

func (s *ProbeSession) Close() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

func (s *ProbeSession) Handshake(timeout time.Duration) (float64, error) {
	// Send exact AmneziaWG obfuscation sequence (I1..I5 + Jc junk, capped at 8 during fast scan)
	for _, pkt := range obf.PreHandshakePackets(s.obfProf, 8) {
		_, _ = s.conn.WriteToUDP(pkt, s.addr)
	}

	initPkt, err := s.buildInitiation()
	if err != nil {
		return 0, err
	}

	t0 := time.Now()
	if _, err := s.conn.WriteToUDP(initPkt, s.addr); err != nil {
		return 0, err
	}

	deadline := t0.Add(timeout)
	buf := make([]byte, 2048)
	for {
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("handshake timeout")
		}
		_ = s.conn.SetReadDeadline(deadline)
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return 0, err
		}
		if n == 92 && buf[0] == 2 && binary.LittleEndian.Uint32(buf[8:12]) == s.selfIdx {
			rttMs := float64(time.Since(t0).Microseconds()) / 1000.0
			if err := s.consumeResponse(buf[:92]); err != nil {
				continue
			}
			return rttMs, nil
		}
	}
}

func (s *ProbeSession) buildInitiation() ([]byte, error) {
	c := b2Hash(wgConstruction)
	h := b2Hash(b2Hash(c, wgIdentifier), s.rPub)

	var ePriv [32]byte
	if _, err := rand.Read(ePriv[:]); err != nil {
		return nil, err
	}
	ePriv[0] &= 248
	ePriv[31] &= 127
	ePriv[31] |= 64
	ePub, err := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	c = b2KDF(c, ePub, 1)[0]
	h = b2Hash(h, ePub)

	dh1, err := curve25519.X25519(ePriv[:], s.rPub)
	if err != nil {
		return nil, err
	}
	ck1 := b2KDF(c, dh1, 2)
	c, k := ck1[0], ck1[1]

	aead1, _ := chacha20poly1305.New(k)
	encStatic := aead1.Seal(nil, wgNonce(0), s.sPub, h)
	h = b2Hash(h, encStatic)

	dh2, err := curve25519.X25519(s.sPriv, s.rPub)
	if err != nil {
		return nil, err
	}
	ck2 := b2KDF(c, dh2, 2)
	c, k = ck2[0], ck2[1]

	aead2, _ := chacha20poly1305.New(k)
	encTS := aead2.Seal(nil, wgNonce(0), tai64nNow(), h)
	h = b2Hash(h, encTS)

	var idxBytes [4]byte
	_, _ = rand.Read(idxBytes[:])
	s.selfIdx = binary.LittleEndian.Uint32(idxBytes[:])
	s.cState = c
	s.hState = h
	s.ePriv = ePriv[:]

	msg := make([]byte, 0, 148)
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 1)
	binary.LittleEndian.PutUint32(hdr[4:8], s.selfIdx)
	msg = append(msg, hdr[:]...)
	msg = append(msg, ePub...)
	msg = append(msg, encStatic...)
	msg = append(msg, encTS...)

	macKey := b2Hash(wgLabelMac1, s.rPub)
	mac1Hasher, _ := blake2s.New128(macKey)
	mac1Hasher.Write(msg)
	msg = append(msg, mac1Hasher.Sum(nil)...)
	msg = append(msg, make([]byte, 16)...)
	return msg, nil
}

func (s *ProbeSession) consumeResponse(resp []byte) error {
	c := s.cState
	h := s.hState
	erPub := resp[12:44]

	c = b2KDF(c, erPub, 1)[0]
	h = b2Hash(h, erPub)

	dh1, err := curve25519.X25519(s.ePriv, erPub)
	if err != nil {
		return err
	}
	c = b2KDF(c, dh1, 1)[0]

	dh2, err := curve25519.X25519(s.sPriv, erPub)
	if err != nil {
		return err
	}
	c = b2KDF(c, dh2, 1)[0]

	ctk := b2KDF(c, s.psk, 3)
	c, tau, k := ctk[0], ctk[1], ctk[2]
	h = b2Hash(h, tau)

	aead, _ := chacha20poly1305.New(k)
	if _, err := aead.Open(nil, wgNonce(0), resp[44:60], h); err != nil {
		return err
	}

	keys := b2KDF(c, nil, 2)
	s.kSend = keys[0]
	s.kRecv = keys[1]
	s.peerIdx = binary.LittleEndian.Uint32(resp[4:8])
	s.counter = 0
	return nil
}

func (s *ProbeSession) sendIP(pkt []byte) error {
	if s.kSend == nil {
		return fmt.Errorf("session not established")
	}
	pad := (16 - (len(pkt) % 16)) % 16
	padded := make([]byte, len(pkt)+pad)
	copy(padded, pkt)

	n := s.counter
	s.counter++

	aead, _ := chacha20poly1305.New(s.kSend)
	ct := aead.Seal(nil, wgNonce(n), padded, nil)

	wire := make([]byte, 16+len(ct))
	binary.LittleEndian.PutUint32(wire[0:4], 4)
	binary.LittleEndian.PutUint32(wire[4:8], s.peerIdx)
	binary.LittleEndian.PutUint64(wire[8:16], n)
	copy(wire[16:], ct)
	_, err := s.conn.WriteToUDP(wire, s.addr)
	return err
}

func (s *ProbeSession) recvIP(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)
	aead, _ := chacha20poly1305.New(s.kRecv)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("recv timeout")
		}
		_ = s.conn.SetReadDeadline(deadline)
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if n < 32 || buf[0] != 4 || binary.LittleEndian.Uint32(buf[4:8]) != s.selfIdx {
			continue
		}
		var nonce [12]byte
		copy(nonce[4:], buf[8:16])
		pt, err := aead.Open(nil, nonce[:], buf[16:n], nil)
		if err != nil || len(pt) == 0 {
			continue
		}
		return pt, nil
	}
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildIPv4Packet(proto byte, src, dst net.IP, payload []byte) []byte {
	total := 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[6] = 0x40 // DF
	pkt[8] = 64   // TTL
	pkt[9] = proto
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	copy(pkt[20:], payload)
	return pkt
}

// PingICMP sends a real ICMP Echo Request inside the tunnel to targetIP and returns RTT in ms.
func (s *ProbeSession) PingICMP(targetIP string, seq uint16, timeout time.Duration) (float64, error) {
	dst := net.ParseIP(targetIP).To4()
	if dst == nil {
		return 0, fmt.Errorf("invalid IPv4 %s", targetIP)
	}
	var idBytes [2]byte
	_, _ = rand.Read(idBytes[:])
	echoID := binary.BigEndian.Uint16(idBytes[:])

	icmp := make([]byte, 16)
	icmp[0] = 8 // Echo Request
	binary.BigEndian.PutUint16(icmp[4:6], echoID)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], []byte("ABIROUTE"))
	binary.BigEndian.PutUint16(icmp[2:4], ipChecksum(icmp))

	ipPkt := buildIPv4Packet(1, s.srcIP, dst, icmp)
	t0 := time.Now()
	if err := s.sendIP(ipPkt); err != nil {
		return 0, err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pt, err := s.recvIP(time.Until(deadline))
		if err != nil {
			return 0, err
		}
		if len(pt) < 28 || (pt[0]>>4) != 4 || pt[9] != 1 {
			continue
		}
		ihl := int(pt[0]&0x0F) * 4
		if len(pt) < ihl+8 {
			continue
		}
		if pt[ihl] == 0 && binary.BigEndian.Uint16(pt[ihl+4:ihl+6]) == echoID {
			return float64(time.Since(t0).Microseconds()) / 1000.0, nil
		}
	}
	return 0, fmt.Errorf("icmp timeout")
}

// QueryColo queries CHAOS TXT "id.server" at 1.1.1.1:53 inside the tunnel to identify the Cloudflare edge city.
func (s *ProbeSession) QueryColo(timeout time.Duration) string {
	var txid [2]byte
	_, _ = rand.Read(txid[:])
	// DNS query: id.server, QTYPE=TXT(16), QCLASS=CH(3)
	dns := []byte{
		txid[0], txid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 'i', 'd', 0x06, 's', 'e', 'r', 'v', 'e', 'r', 0x00,
		0x00, 0x10, 0x00, 0x03,
	}

	udp := make([]byte, 8+len(dns))
	binary.BigEndian.PutUint16(udp[0:2], 51821)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], dns)

	ipPkt := buildIPv4Packet(17, s.srcIP, net.IPv4(1, 1, 1, 1), udp)
	if err := s.sendIP(ipPkt); err != nil {
		return ""
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pt, err := s.recvIP(time.Until(deadline))
		if err != nil {
			return ""
		}
		if len(pt) < 28 || (pt[0]>>4) != 4 || pt[9] != 17 {
			continue
		}
		ihl := int(pt[0]&0x0F) * 4
		if len(pt) < ihl+8+12 {
			continue
		}
		resp := pt[ihl+8:]
		if resp[0] != txid[0] || resp[1] != txid[1] {
			continue
		}
		// Extract last printable TXT string (e.g. "FRA" or "fra01")
		if len(resp) > 28 {
			txtLen := int(resp[len(resp)-4])
			if txtLen >= 3 && txtLen <= 12 && len(resp) >= txtLen+1 {
				// Scan from end for 3-letter IATA prefix
				for idx := len(resp) - 1; idx >= 12; idx-- {
					ln := int(resp[idx])
					if ln >= 3 && ln <= 16 && idx+1+ln <= len(resp) {
						candidate := string(resp[idx+1 : idx+1+ln])
						valid := true
						for _, ch := range candidate[:3] {
							if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
								valid = false
								break
							}
						}
						if valid {
							return candidate
						}
					}
				}
			}
		}
	}
	return ""
}

// ScanNodes concurrently scans ~430 Cloudflare WARP endpoints with real obfuscation,
// then refines the top 12 with real in-tunnel ICMP data verification and Cloudflare city lookup.
func ScanNodes(ctx context.Context, acct *config.WarpAccount, prof obf.Profile, bindLocalIP string, progress func(done, total int)) ([]config.NodeInfo, error) {
	if acct == nil || acct.PrivateKey == "" {
		return nil, fmt.Errorf("профиль WARP не создан")
	}

	var candidates []string
	for _, ip := range warpScanIPs {
		for _, port := range warpScanPorts {
			candidates = append(candidates, fmt.Sprintf("%s:%d", ip, port))
		}
	}
	total := len(candidates)

	type hsHit struct {
		ep string
		ms float64
	}
	var (
		mu   sync.Mutex
		hits []hsHit
		done atomic.Int32
	)

	sem := make(chan struct{}, 48)
	var wg sync.WaitGroup
	for _, ep := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(endpoint string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			sess, err := NewProbeSession(acct.PrivateKey, acct.PeerPublicKey, "", acct.IPv4, endpoint, prof, bindLocalIP)
			if err == nil {
				ms, err := sess.Handshake(1100 * time.Millisecond)
				sess.Close()
				if err == nil {
					mu.Lock()
					hits = append(hits, hsHit{ep: endpoint, ms: ms})
					mu.Unlock()
				}
			}
			cur := int(done.Add(1))
			if progress != nil && (cur%12 == 0 || cur == total) {
				progress(cur, total)
			}
		}(ep)
	}
	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(hits) == 0 {
		return nil, nil
	}

	sort.Slice(hits, func(i, j int) bool { return hits[i].ms < hits[j].ms })
	// Pick diverse IPs first among fastest endpoints
	var shortlist []hsHit
	seenIP := map[string]int{}
	for _, h := range hits {
		host, _, _ := net.SplitHostPort(h.ep)
		if seenIP[host] < 2 {
			shortlist = append(shortlist, h)
			seenIP[host]++
		}
		if len(shortlist) >= 14 {
			break
		}
	}

	var nodes []config.NodeInfo
	var rwg sync.WaitGroup
	for _, h := range shortlist {
		rwg.Add(1)
		go func(cand hsHit) {
			defer rwg.Done()
			if ctx.Err() != nil {
				return
			}
			sess, err := NewProbeSession(acct.PrivateKey, acct.PeerPublicKey, "", acct.IPv4, cand.ep, prof, bindLocalIP)
			if err != nil {
				return
			}
			defer sess.Close()
			hsMs, err := sess.Handshake(1400 * time.Millisecond)
			if err != nil {
				return
			}

			var rtts []float64
			const probes = 4
			for p := uint16(1); p <= probes; p++ {
				if ms, err := sess.PingICMP("1.1.1.1", p, 900*time.Millisecond); err == nil {
					rtts = append(rtts, ms)
				}
			}
			if len(rtts) == 0 {
				return // Handshake passed, but ISP dropped WireGuard transport packets!
			}

			coloRaw := sess.QueryColo(700 * time.Millisecond)
			code, city, country := warp.LookupColo(coloRaw)

			sort.Float64s(rtts)
			med := rtts[len(rtts)/2]
			var mean float64
			for _, v := range rtts {
				mean += v
			}
			mean /= float64(len(rtts))
			var variance float64
			for _, v := range rtts {
				d := v - mean
				variance += d * d
			}
			jitter := math.Sqrt(variance / float64(len(rtts)))
			loss := int(math.Round(float64(probes-len(rtts)) * 100.0 / float64(probes)))
			score := int(math.Round(med + 1.5*jitter + float64(5*loss)))

			mu.Lock()
			nodes = append(nodes, config.NodeInfo{
				Endpoint:     cand.ep,
				ColoCode:     code,
				City:         city,
				Country:      country,
				HandshakeMs:  int(math.Round(hsMs)),
				TunnelPingMs: int(math.Round(med)),
				JitterMs:     int(math.Round(jitter)),
				LossPct:      loss,
				Score:        score,
			})
			mu.Unlock()
		}(h)
	}
	rwg.Wait()

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Score < nodes[j].Score })
	return nodes, nil
}

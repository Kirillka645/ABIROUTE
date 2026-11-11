package obf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

var quicV1Salt, _ = hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

func quicVarint(v uint64) []byte {
	switch {
	case v < 0x40:
		return []byte{byte(v)}
	case v < 0x4000:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(v)|0x4000)
		return b[:]
	case v < 0x40000000:
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v)|0x80000000)
		return b[:]
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v|0xC000000000000000)
		return b[:]
	}
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := []byte("tls13 " + label)
	info := make([]byte, 0, 3+len(full)+1)
	info = append(info, byte(length>>8), byte(length), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0x00)

	var out, prev []byte
	for i := byte(1); len(out) < length; i++ {
		mac := hmac.New(sha256.New, secret)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{i})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

func quicClientKeys(dcid []byte) (key, iv, hp []byte) {
	mac := hmac.New(sha256.New, quicV1Salt)
	mac.Write(dcid)
	initialSecret := mac.Sum(nil)
	clientIn := hkdfExpandLabel(initialSecret, "client in", 32)
	return hkdfExpandLabel(clientIn, "quic key", 16),
		hkdfExpandLabel(clientIn, "quic iv", 12),
		hkdfExpandLabel(clientIn, "quic hp", 16)
}

func buildTLSClientHello(sni string, scid []byte) []byte {
	host := []byte(strings.TrimSpace(sni))
	if len(host) == 0 {
		host = []byte("www.google.com")
	}

	ext := func(t uint16, data []byte) []byte {
		b := make([]byte, 4+len(data))
		binary.BigEndian.PutUint16(b[0:2], t)
		binary.BigEndian.PutUint16(b[2:4], uint16(len(data)))
		copy(b[4:], data)
		return b
	}

	tp := func(id uint64, val []byte) []byte {
		out := append(quicVarint(id), quicVarint(uint64(len(val)))...)
		return append(out, val...)
	}

	var params bytes.Buffer
	params.Write(tp(0x01, quicVarint(30000)))
	params.Write(tp(0x03, quicVarint(1472)))
	params.Write(tp(0x04, quicVarint(1048576)))
	params.Write(tp(0x05, quicVarint(262144)))
	params.Write(tp(0x06, quicVarint(262144)))
	params.Write(tp(0x07, quicVarint(262144)))
	params.Write(tp(0x08, quicVarint(100)))
	params.Write(tp(0x09, quicVarint(100)))
	params.Write(tp(0x0e, quicVarint(4)))
	params.Write(tp(0x0f, scid))

	var priv [32]byte
	_, _ = rand.Read(priv[:])
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)

	sniData := make([]byte, 5+len(host))
	binary.BigEndian.PutUint16(sniData[0:2], uint16(len(host)+3))
	sniData[2] = 0
	binary.BigEndian.PutUint16(sniData[3:5], uint16(len(host)))
	copy(sniData[5:], host)

	groups, _ := hex.DecodeString("0006001d00170018")
	sigAlgs, _ := hex.DecodeString("001004030804040105030805050108060601")

	ks := make([]byte, 6+32)
	binary.BigEndian.PutUint16(ks[0:2], 36)
	binary.BigEndian.PutUint16(ks[2:4], 0x001d)
	binary.BigEndian.PutUint16(ks[4:6], 32)
	copy(ks[6:], pub)

	var exts bytes.Buffer
	exts.Write(ext(0x0000, sniData))
	exts.Write(ext(0x000a, groups))
	exts.Write(ext(0x0010, []byte{0x00, 0x03, 0x02, 'h', '3'}))
	exts.Write(ext(0x000d, sigAlgs))
	exts.Write(ext(0x0033, ks))
	exts.Write(ext(0x002d, []byte{0x01, 0x01}))
	exts.Write(ext(0x002b, []byte{0x02, 0x03, 0x04}))
	exts.Write(ext(0x0039, params.Bytes()))

	var rnd [32]byte
	_, _ = rand.Read(rnd[:])

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(rnd[:])
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03})
	body.Write([]byte{0x01, 0x00})
	extBytes := exts.Bytes()
	body.Write([]byte{byte(len(extBytes) >> 8), byte(len(extBytes))})
	body.Write(extBytes)

	rawBody := body.Bytes()
	out := make([]byte, 4+len(rawBody))
	out[0] = 0x01
	out[1] = byte(len(rawBody) >> 16)
	out[2] = byte(len(rawBody) >> 8)
	out[3] = byte(len(rawBody))
	copy(out[4:], rawBody)
	return out
}

// BuildQUICInitial constructs a real >=1200-byte RFC 9001 QUIC v1 Initial packet with TLS 1.3 ClientHello.
func BuildQUICInitial(sni string) ([]byte, error) {
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)

	hello := buildTLSClientHello(sni, scid)
	var payload bytes.Buffer
	payload.WriteByte(0x06) // CRYPTO frame
	payload.Write(quicVarint(0))
	payload.Write(quicVarint(uint64(len(hello))))
	payload.Write(hello)

	pnLen := 2
	var head bytes.Buffer
	head.WriteByte(byte(0xC0 | (pnLen - 1)))
	head.Write([]byte{0x00, 0x00, 0x00, 0x01}) // QUIC v1
	head.WriteByte(byte(len(dcid)))
	head.Write(dcid)
	head.WriteByte(byte(len(scid)))
	head.Write(scid)
	head.Write(quicVarint(0)) // token length 0

	if pad := 1200 - (head.Len() + 2 + pnLen + payload.Len() + 16); pad > 0 {
		payload.Write(make([]byte, pad))
	}

	var lenField [2]byte
	binary.BigEndian.PutUint16(lenField[:], uint16(pnLen+payload.Len()+16)|0x4000)
	head.Write(lenField[:])
	head.Write(make([]byte, pnLen)) // packet number 0

	hdr := head.Bytes()
	key, iv, hp := quicClientKeys(dcid)

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, iv, payload.Bytes(), hdr)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	var mask [16]byte
	sampleOffset := 4 - pnLen
	hpBlock.Encrypt(mask[:], ct[sampleOffset:sampleOffset+16])

	out := make([]byte, len(hdr)+len(ct))
	copy(out, hdr)
	pnOff := len(hdr) - pnLen
	out[0] ^= mask[0] & 0x0F
	for i := 0; i < pnLen; i++ {
		out[pnOff+i] ^= mask[1+i]
	}
	copy(out[len(hdr):], ct)
	return out, nil
}

// BuildDNSQuery constructs a realistic DNS A query with EDNS0 OPT record.
func BuildDNSQuery(domain string) []byte {
	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if domain == "" {
		domain = "www.google.com"
	}
	var txid [2]byte
	_, _ = rand.Read(txid[:])

	var buf bytes.Buffer
	buf.Write(txid[:])
	buf.Write([]byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	for _, label := range strings.Split(domain, ".") {
		if len(label) > 0 && len(label) < 64 {
			buf.WriteByte(byte(len(label)))
			buf.WriteString(label)
		}
	}
	buf.WriteByte(0x00)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01}) // QTYPE=A, QCLASS=IN
	// EDNS0 OPT pseudo-RR (payload size 1232)
	buf.Write([]byte{0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return buf.Bytes()
}

// BuildSIPOptions constructs a realistic SIP/2.0 OPTIONS keepalive datagram for VoIP mimicry.
func BuildSIPOptions(domain string) []byte {
	if strings.TrimSpace(domain) == "" {
		domain = "sip.cloudflare.com"
	}
	var branch [6]byte
	_, _ = rand.Read(branch[:])
	msg := fmt.Sprintf(
		"OPTIONS sip:%s SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK%x;rport\r\nMax-Forwards: 70\r\nTo: <sip:%s>\r\nFrom: <sip:client@%s>;tag=%x\r\nCall-ID: %x@%s\r\nCSeq: 1 OPTIONS\r\nAccept: application/sdp\r\nContent-Length: 0\r\n\r\n",
		domain, branch[:], domain, domain, branch[:3], branch[:], domain,
	)
	return []byte(msg)
}

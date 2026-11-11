package obf

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Profile struct {
	ID          string
	Title       string
	Description string
	Jc          int
	Jmin        int
	Jmax        int
	S1          int
	S2          int
	H1          string
	H2          string
	H3          string
	H4          string
	I           map[string]string
}

var cpsTagRe = regexp.MustCompile(`(?i)<\s*(b|rc|rd|r|c|t|d|ds|dz)(?:\s+([^>]*))?>`)

func ToCPS(pkt []byte) string {
	return "<b 0x" + hex.EncodeToString(pkt) + ">"
}

// RenderCPS evaluates an AmneziaWG 2.0/3.0 I1..I5 CPS packet specification into raw UDP bytes.
func RenderCPS(spec string) ([]byte, error) {
	matches := cpsTagRe.FindAllStringSubmatch(spec, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("empty CPS specification")
	}
	var out []byte
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const digits = "0123456789"

	for _, m := range matches {
		tag := strings.ToLower(strings.TrimSpace(m[1]))
		arg := strings.TrimSpace(m[2])
		switch tag {
		case "b":
			hx := strings.TrimPrefix(strings.TrimPrefix(arg, "0x"), "0X")
			if len(hx) == 0 || len(hx)%2 != 0 {
				return nil, fmt.Errorf("invalid hex in <b> tag")
			}
			b, err := hex.DecodeString(hx)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		case "r", "rc", "rd":
			n, err := strconv.Atoi(arg)
			if err != nil || n <= 0 || n > 1400 {
				return nil, fmt.Errorf("invalid length in <%s>: %q", tag, arg)
			}
			switch tag {
			case "r":
				buf := make([]byte, n)
				_, _ = rand.Read(buf)
				out = append(out, buf...)
			case "rc":
				for i := 0; i < n; i++ {
					idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
					out = append(out, letters[idx.Int64()])
				}
			case "rd":
				for i := 0; i < n; i++ {
					idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
					out = append(out, digits[idx.Int64()])
				}
			}
		case "c":
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], 1)
			out = append(out, b[:]...)
		case "t":
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(time.Now().Unix()))
			out = append(out, b[:]...)
		case "d", "ds", "dz":
			// Data-dependent tags ignored in standalone I-packets
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("rendered CPS packet is empty")
	}
	return out, nil
}

// BuildProfile builds the AmneziaWG obfuscation profile for a given protocol mode and SNI.
func BuildProfile(mode, sni string) Profile {
	if strings.TrimSpace(sni) == "" {
		sni = "www.google.com"
	}
	base := Profile{
		ID:   mode,
		Jc:   4,
		Jmin: 40,
		Jmax: 70,
		S1:   0,
		S2:   0,
		H1:   "1",
		H2:   "2",
		H3:   "3",
		H4:   "4",
		I:    map[string]string{},
	}

	switch mode {
	case "awg_quic", "auto", "":
		base.ID = "awg_quic"
		base.Title = "AmneziaWG 2.0 · Маскировка QUIC (HTTP/3)"
		base.Description = "Настоящий TLS 1.3 ClientHello (QUIC Initial >=1200 байт) + мусорные пакеты перед рукопожатием"
		if pkt, err := BuildQUICInitial(sni); err == nil {
			base.I["I1"] = ToCPS(pkt)
			base.I["I2"] = "<b 0xc00000000108><r 16>"
		}
	case "awg_dns":
		base.Title = "AmneziaWG 2.0 · Маскировка DNS (EDNS0)"
		base.Description = "Имитация стандартного DNS-запроса браузера перед открытием игрового туннеля"
		base.Jc = 6
		base.I["I1"] = ToCPS(BuildDNSQuery(sni))
	case "awg_sip":
		base.Title = "AmneziaWG 2.0 · Маскировка VoIP (SIP)"
		base.Description = "Имитация голосового вызова SIP/2.0 UDP + усиленная серия мусорных пакетов"
		base.Jc = 8
		base.Jmin = 50
		base.Jmax = 180
		base.I["I1"] = ToCPS(BuildSIPOptions(sni))
	case "awg_junk":
		base.Title = "AmneziaWG · Усиленный шум (Jc ×90)"
		base.Description = "Классическая обфускация длинной серией случайных пакетов без I1"
		base.Jc = 90
		base.Jmin = 23
		base.Jmax = 911
	}
	return base
}

// PreHandshakePackets generates the exact sequence of UDP packets (I1..I5 followed by Jc junk packets)
// sent prior to a WireGuard/AmneziaWG Handshake Initiation.
func PreHandshakePackets(p Profile, maxJunk int) [][]byte {
	var pkts [][]byte
	for idx := 1; idx <= 5; idx++ {
		key := fmt.Sprintf("I%d", idx)
		if spec := p.I[key]; spec != "" {
			if raw, err := RenderCPS(spec); err == nil {
				pkts = append(pkts, raw)
			}
		}
	}
	jc := p.Jc
	if maxJunk > 0 && jc > maxJunk {
		jc = maxJunk
	}
	if jc > 0 && p.Jmax > 0 {
		lo := p.Jmin
		hi := p.Jmax
		if lo < 1 {
			lo = 1
		}
		if hi < lo {
			hi = lo
		}
		span := int64(hi - lo + 1)
		for i := 0; i < jc; i++ {
			off, _ := rand.Int(rand.Reader, big.NewInt(span))
			buf := make([]byte, lo+int(off.Int64()))
			_, _ = rand.Read(buf)
			pkts = append(pkts, buf)
		}
	}
	return pkts
}

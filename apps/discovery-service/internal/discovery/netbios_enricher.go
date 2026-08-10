package discovery

import (
    "context"
	"crypto/rand"
    "encoding/binary"
    "fmt"
    "net"
	"strings"
    "time"

    "github.com/user/lias-dis/shared/models"
)

const (
	netBIOSNodeStatusType = 0x0021
	netBIOSClassIN        = 0x0001
)

type NetBIOSEnricher struct {
    ctx    context.Context
    cancel context.CancelFunc
}

func NewNetBIOSEnricher() *NetBIOSEnricher { return &NetBIOSEnricher{} }
func (e *NetBIOSEnricher) Name() string { return "netbios" }

func (e *NetBIOSEnricher) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    return nil
}

func (e *NetBIOSEnricher) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    return nil
}

func (e *NetBIOSEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || d.CurrentIP == "" {
        return nil, fmt.Errorf("cannot enrich without IP")
    }
	if ip := net.ParseIP(d.CurrentIP); ip == nil || ip.To4() == nil {
		return nil, nil
	}
    names, err := e.queryNodeStatus(ctx, d.CurrentIP)
    if err != nil || len(names) == 0 {
        return nil, nil
    }
	enr := &models.Enrichment{Source: e.Name(), Confidence: 0.6, Raw: make(map[string]interface{})}
	serviceSet := make(map[string]struct{})
	for _, name := range names {
		isGroup := name.Flags&0x8000 != 0
		if name.Suffix == 0x00 && !isGroup && enr.Hostname == "" && validNetBIOSHostname(name.Name) {
			enr.Hostname = name.Name
    }
		if name.Suffix == 0x1C && isGroup {
			serviceSet["domain_controller"] = struct{}{}
        }
		if name.Suffix == 0x20 && !isGroup {
			serviceSet["file_server"] = struct{}{}
        }
        }
	for _, service := range []string{"domain_controller", "file_server"} {
		if _, ok := serviceSet[service]; ok {
			enr.Services = append(enr.Services, service)
    }
    }
	if enr.Hostname == "" && len(enr.Services) == 0 {
		return nil, nil
    }
        return enr, nil
    }

type netbiosName struct {
    Name   string
    Suffix byte
    Flags  uint16
}

func (e *NetBIOSEnricher) queryNodeStatus(ctx context.Context, ip string) ([]netbiosName, error) {
    searchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ip, "137"))
    if err != nil {
        return nil, err
    }
    conn, err := net.DialUDP("udp4", nil, addr)
    if err != nil {
        return nil, err
    }
    defer conn.Close()
    deadline, _ := searchCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
        return nil, err
    }
	transactionID := binary.BigEndian.Uint16(idBytes[:])
	request := buildNodeStatusRequest(transactionID)
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
    n, err := conn.Read(buf)
    if err != nil {
        return nil, err
    }
	return parseNodeStatusResponse(buf[:n], transactionID)
}

func buildNodeStatusRequest(transactionID uint16) []byte {
	request := make([]byte, 50)
	binary.BigEndian.PutUint16(request[0:2], transactionID)
	binary.BigEndian.PutUint16(request[4:6], 1)
	request[12] = 32
	var wildcard [16]byte
	wildcard[0] = '*'
	encodeNetBIOSName(wildcard[:], request[13:45])
	request[45] = 0
	binary.BigEndian.PutUint16(request[46:48], netBIOSNodeStatusType)
	binary.BigEndian.PutUint16(request[48:50], netBIOSClassIN)
	return request
}

func encodeNetBIOSName(name []byte, dst []byte) {
    for i := 0; i < 16; i++ {
        c := name[i]
		dst[i*2] = 'A' + c>>4
		dst[i*2+1] = 'A' + c&0x0f
    }
}

func parseNodeStatusResponse(data []byte, expectedTransactionID uint16) ([]netbiosName, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("netbios packet shorter than DNS header")
    }
	if binary.BigEndian.Uint16(data[0:2]) != expectedTransactionID {
		return nil, fmt.Errorf("netbios transaction ID mismatch")
    }
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return nil, fmt.Errorf("netbios packet is not a response")
	}
	if flags&0x7800 != 0 {
		return nil, fmt.Errorf("unexpected netbios opcode")
	}
	if flags&0x000f != 0 {
		return nil, fmt.Errorf("netbios response code %d", flags&0x000f)
	}
	questions := int(binary.BigEndian.Uint16(data[4:6]))
	answers := int(binary.BigEndian.Uint16(data[6:8]))
	if questions > 16 || answers > 64 {
		return nil, fmt.Errorf("netbios record count exceeds limit")
	}
	offset := 12
	var err error
	for i := 0; i < questions; i++ {
		offset, err = skipDNSName(data, offset)
		if err != nil || offset+4 > len(data) {
			return nil, fmt.Errorf("malformed netbios question")
		}
		offset += 4
	}
	for i := 0; i < answers; i++ {
		offset, err = skipDNSName(data, offset)
		if err != nil || offset+10 > len(data) {
			return nil, fmt.Errorf("malformed netbios answer")
		}
		rrType := binary.BigEndian.Uint16(data[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		rdataLength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10
		if rdataLength < 0 || offset+rdataLength > len(data) {
			return nil, fmt.Errorf("netbios RDATA exceeds packet")
		}
		if rrType == netBIOSNodeStatusType && rrClass&0x7fff == netBIOSClassIN {
			return parseNodeStatusRDATA(data[offset : offset+rdataLength])
		}
		offset += rdataLength
	}
	return nil, fmt.Errorf("netbios response contains no NBSTAT answer")
    }

func skipDNSName(data []byte, offset int) (int, error) {
	if offset < 0 || offset >= len(data) {
		return 0, fmt.Errorf("DNS name offset out of bounds")
	}
	position, consumedEnd := offset, -1
	seen := make(map[int]struct{})
	for steps := 0; steps < 128; steps++ {
		if position >= len(data) {
			return 0, fmt.Errorf("truncated DNS name")
		}
		if _, exists := seen[position]; exists {
			return 0, fmt.Errorf("DNS compression loop")
		}
		seen[position] = struct{}{}
		length := int(data[position])
		if length&0xc0 == 0xc0 {
			if position+1 >= len(data) {
				return 0, fmt.Errorf("truncated DNS pointer")
			}
			pointer := (length&0x3f)<<8 | int(data[position+1])
			if pointer >= len(data) {
				return 0, fmt.Errorf("DNS pointer out of bounds")
			}
			if consumedEnd < 0 {
				consumedEnd = position + 2
			}
			position = pointer
			continue
		}
		if length&0xc0 != 0 || length > 63 {
			return 0, fmt.Errorf("invalid DNS label length")
		}
		position++
		if length == 0 {
			if consumedEnd >= 0 {
				return consumedEnd, nil
			}
			return position, nil
		}
		if position+length > len(data) {
			return 0, fmt.Errorf("truncated DNS label")
		}
		position += length
	}
	return 0, fmt.Errorf("DNS name exceeds pointer limit")
    }

func parseNodeStatusRDATA(data []byte) ([]netbiosName, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty NBSTAT RDATA")
	}
	count := int(data[0])
	if count > 100 || 1+count*18 > len(data) {
		return nil, fmt.Errorf("NBSTAT name table exceeds RDATA")
	}
	names := make([]netbiosName, 0, count)
	offset := 1
	for i := 0; i < count; i++ {
        entry := data[offset : offset+18]
		nameBytes := entry[:15]
		for _, value := range nameBytes {
			if value != 0 && (value < 0x20 || value > 0x7e) {
				return nil, fmt.Errorf("NBSTAT name contains control bytes")
        }
		}
		name := strings.TrimRight(string(nameBytes), " \x00")
		names = append(names, netbiosName{Name: name, Suffix: entry[15], Flags: binary.BigEndian.Uint16(entry[16:18])})
        offset += 18
    }
    return names, nil
}

func validNetBIOSHostname(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

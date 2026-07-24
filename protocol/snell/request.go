package snell

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/protocol"
)

func makeTCPRequest(userKey string, destination protocol.Metadata, command byte) ([]byte, error) {
	if command != commandConnect && command != commandConnectV2 {
		return nil, fmt.Errorf("snell: invalid connect command %d", command)
	}
	host := destination.Hostname
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("snell: invalid destination host %q", host)
	}
	request := make([]byte, 3+len(userKey)+1+len(host)+2)
	request[0] = requestVersion
	request[1] = command
	request[2] = byte(len(userKey))
	offset := 3
	copy(request[offset:], userKey)
	offset += len(userKey)
	request[offset] = byte(len(host))
	offset++
	copy(request[offset:], host)
	offset += len(host)
	binary.BigEndian.PutUint16(request[offset:], destination.Port)
	return request, nil
}

func makeUDPRequest(userKey string) []byte {
	request := make([]byte, 3+len(userKey))
	request[0] = requestVersion
	request[1] = commandUDP
	request[2] = byte(len(userKey))
	copy(request[3:], userKey)
	return request
}

func readReply(r io.Reader) error {
	var prefix [1]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return err
	}
	switch prefix[0] {
	case replyTunnel:
		return nil
	case replyError:
		var errorHeader [2]byte
		if _, err := io.ReadFull(r, errorHeader[:]); err != nil {
			return err
		}
		message := make([]byte, int(errorHeader[1]))
		if _, err := io.ReadFull(r, message); err != nil {
			return err
		}
		return fmt.Errorf("snell: server error %d: %s", errorHeader[0], message)
	default:
		return fmt.Errorf("%w: opcode %d", ErrBadReply, prefix[0])
	}
}

func appendUDPRequest(payload []byte, destination protocol.Metadata) ([]byte, error) {
	return appendUDPRequestLimit(payload, destination, maxPayloadLen)
}

func appendUDPRequestLimit(payload []byte, destination protocol.Metadata, limit int) ([]byte, error) {
	packet := make([]byte, 0, 1+2+net.IPv6len+2+len(payload))
	packet = append(packet, udpForward)
	switch destination.Type {
	case protocol.MetadataTypeIPv4:
		ip, err := netip.ParseAddr(destination.Hostname)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("snell: invalid IPv4 destination %q", destination.Hostname)
		}
		packet = append(packet, 0, 4)
		packet = append(packet, ip.AsSlice()...)
	case protocol.MetadataTypeIPv6:
		ip, err := netip.ParseAddr(destination.Hostname)
		if err != nil || !ip.Is6() {
			return nil, fmt.Errorf("snell: invalid IPv6 destination %q", destination.Hostname)
		}
		packet = append(packet, 0, 6)
		packet = append(packet, ip.AsSlice()...)
	case protocol.MetadataTypeDomain:
		if len(destination.Hostname) == 0 || len(destination.Hostname) > 255 {
			return nil, fmt.Errorf("snell: invalid UDP domain %q", destination.Hostname)
		}
		packet = append(packet, byte(len(destination.Hostname)))
		packet = append(packet, destination.Hostname...)
	default:
		return nil, fmt.Errorf("snell: unsupported UDP address type %d", destination.Type)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], destination.Port)
	packet = append(packet, port[:]...)
	packet = append(packet, payload...)
	if len(packet) > limit {
		return nil, ErrPayloadTooLarge
	}
	return packet, nil
}

func parseUDPResponse(packet []byte) (netip.AddrPort, []byte, error) {
	if len(packet) < 1+2 {
		return netip.AddrPort{}, nil, ErrBadRecord
	}
	var ip netip.Addr
	var offset int
	switch packet[0] {
	case 4:
		offset = 1 + net.IPv4len
		if len(packet) < offset+2 {
			return netip.AddrPort{}, nil, ErrBadRecord
		}
		var raw [4]byte
		copy(raw[:], packet[1:offset])
		ip = netip.AddrFrom4(raw)
	case 6:
		offset = 1 + net.IPv6len
		if len(packet) < offset+2 {
			return netip.AddrPort{}, nil, ErrBadRecord
		}
		var raw [16]byte
		copy(raw[:], packet[1:offset])
		ip = netip.AddrFrom16(raw)
	default:
		return netip.AddrPort{}, nil, fmt.Errorf("snell: invalid UDP response address type %d", packet[0])
	}
	port := binary.BigEndian.Uint16(packet[offset : offset+2])
	return netip.AddrPortFrom(ip, port), packet[offset+2:], nil
}

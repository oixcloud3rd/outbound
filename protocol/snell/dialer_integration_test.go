package snell

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/stretchr/testify/require"
)

func TestDialerTCPRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []ClientOptions{
		{Version: Version4},
		{Version: Version5},
		{Version: Version6, Mode: "default"},
		{Version: Version6, Mode: "unshaped"},
		{Version: Version6, Mode: "unsafe-raw"},
	}
	for _, options := range tests {
		t.Run(clientOptionsName(options), func(t *testing.T) {
			base := &pipeDialer{serve: func(raw netproxy.Conn) {
				record := testServerRecord(raw, []byte(testPSKFor(options.Version)), options)
				command, host, port, err := readTCPRequest(record)
				require.NoError(t, err)
				if options.Version == Version6 {
					require.Equal(t, commandConnectV2, command)
				} else {
					require.Equal(t, commandConnect, command)
				}
				require.Equal(t, "destination.example", host)
				require.Equal(t, uint16(443), port)
				payload := make([]byte, len("round-trip"))
				_, err = io.ReadFull(record, payload)
				require.NoError(t, err)
				_, err = record.Write(append([]byte{replyTunnel}, payload...))
				require.NoError(t, err)
				require.NoError(t, testServerEOF(record))
			}}
			dialer, err := NewDialer(base, protocol.Header{
				ProxyAddress: "proxy.example:443",
				Password:     testPSKFor(options.Version),
				Feature1:     options,
			})
			require.NoError(t, err)
			conn, err := dialer.DialContext(context.Background(), "tcp", "destination.example:443")
			require.NoError(t, err)
			_, err = conn.Write([]byte("round-trip"))
			require.NoError(t, err)
			response, err := io.ReadAll(conn)
			require.NoError(t, err)
			require.Equal(t, []byte("round-trip"), response)
			require.NoError(t, conn.Close())
		})
	}
}

func TestDialerUDPRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []ClientOptions{
		{Version: Version4},
		{Version: Version6, Mode: "default"},
		{Version: Version6, Mode: "unshaped"},
		{Version: Version6, Mode: "unsafe-raw"},
	}
	for _, options := range tests {
		t.Run(clientOptionsName(options), func(t *testing.T) {
			base := &pipeDialer{serve: func(raw netproxy.Conn) {
				record := testServerRecord(raw, []byte(testPSKFor(options.Version)), options)
				require.NoError(t, readUDPRequest(record))
				_, err := record.Write([]byte{replyTunnel})
				require.NoError(t, err)
				packet, err := testServerReadPacket(record)
				require.NoError(t, err)
				request, err := parseUDPRequestForTest(packet)
				require.NoError(t, err)
				response := []byte{4, 203, 0, 113, 9, 0x01, 0xbb}
				response = append(response, request...)
				require.NoError(t, testServerWritePacket(record, response))
			}}
			dialer, err := NewDialer(base, protocol.Header{
				ProxyAddress: "proxy.example:443",
				Password:     testPSKFor(options.Version),
				Feature1:     options,
			})
			require.NoError(t, err)
			conn, err := dialer.DialContext(context.Background(), "udp", "destination.example:443")
			require.NoError(t, err)
			packetConn := conn.(netproxy.PacketConn)
			_, err = packetConn.Write([]byte("datagram"))
			require.NoError(t, err)
			buffer := make([]byte, 64)
			n, source, err := packetConn.ReadFrom(buffer)
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddrPort("203.0.113.9:443"), source)
			require.Equal(t, []byte("datagram"), buffer[:n])
			require.NoError(t, packetConn.Close())
		})
	}
}

func TestDialerConnectionReuse(t *testing.T) {
	t.Parallel()
	for _, options := range []ClientOptions{
		{Version: Version4, Reuse: true},
		{Version: Version6, Mode: "unshaped", Reuse: true},
	} {
		t.Run(clientOptionsName(options), func(t *testing.T) {
			var physicalConnections atomic.Int32
			base := &pipeDialer{serve: func(raw netproxy.Conn) {
				physicalConnections.Add(1)
				record := testServerRecord(raw, []byte(testPSKFor(options.Version)), options)
				for requestIndex := 0; requestIndex < 2; requestIndex++ {
					command, _, _, err := readTCPRequest(record)
					require.NoError(t, err)
					require.Equal(t, commandConnectV2, command)
					payload := make([]byte, len("reuse"))
					_, err = io.ReadFull(record, payload)
					require.NoError(t, err)
					one := make([]byte, 1)
					_, err = record.Read(one)
					require.ErrorIs(t, err, io.EOF)
					_, err = record.Write(append([]byte{replyTunnel}, payload...))
					require.NoError(t, err)
					require.NoError(t, testServerEOF(record))
				}
			}}
			dialer, err := NewDialer(base, protocol.Header{
				ProxyAddress: "proxy.example:443",
				Password:     testPSKFor(options.Version),
				Feature1:     options,
			})
			require.NoError(t, err)
			for requestIndex := 0; requestIndex < 2; requestIndex++ {
				conn, err := dialer.DialContext(context.Background(), "tcp", "destination.example:443")
				require.NoError(t, err)
				_, err = conn.Write([]byte("reuse"))
				require.NoError(t, err)
				require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())
				response, err := io.ReadAll(conn)
				require.NoError(t, err)
				require.Equal(t, []byte("reuse"), response)
				require.NoError(t, conn.Close())
			}
			require.Equal(t, int32(1), physicalConnections.Load())
		})
	}
}

type testRecord interface {
	netproxy.Conn
	readPacket() ([]byte, error)
	writePacket([]byte) error
	writeEOF() error
}

func testServerRecord(raw netproxy.Conn, psk []byte, options ClientOptions) testRecord {
	if options.Version == Version6 {
		mode, _ := parseV6Mode(options.Mode)
		return newV6RecordConn(raw, psk, mode)
	}
	return newV4RecordConn(raw, psk, false)
}

func testServerEOF(record testRecord) error                  { return record.writeEOF() }
func testServerReadPacket(record testRecord) ([]byte, error) { return record.readPacket() }
func testServerWritePacket(record testRecord, packet []byte) error {
	return record.writePacket(packet)
}

func readTCPRequest(r io.Reader) (byte, string, uint16, error) {
	var prefix [3]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return 0, "", 0, err
	}
	if prefix[0] != requestVersion || prefix[1] != commandConnect && prefix[1] != commandConnectV2 {
		return 0, "", 0, ErrBadRecord
	}
	if _, err := io.CopyN(io.Discard, r, int64(prefix[2])); err != nil {
		return 0, "", 0, err
	}
	var hostLen [1]byte
	if _, err := io.ReadFull(r, hostLen[:]); err != nil {
		return 0, "", 0, err
	}
	host := make([]byte, int(hostLen[0]))
	if _, err := io.ReadFull(r, host); err != nil {
		return 0, "", 0, err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return 0, "", 0, err
	}
	return prefix[1], string(host), binary.BigEndian.Uint16(port[:]), nil
}

func readUDPRequest(r io.Reader) error {
	var prefix [3]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return err
	}
	if prefix[0] != requestVersion || prefix[1] != commandUDP {
		return ErrBadRecord
	}
	_, err := io.CopyN(io.Discard, r, int64(prefix[2]))
	return err
}

func parseUDPRequestForTest(packet []byte) ([]byte, error) {
	if len(packet) < 2 || packet[0] != udpForward {
		return nil, ErrBadRecord
	}
	offset := 2 + int(packet[1]) + 2
	if packet[1] == 0 {
		if len(packet) < 3 {
			return nil, ErrBadRecord
		}
		if packet[2] == 4 {
			offset = 3 + net.IPv4len + 2
		} else {
			offset = 3 + net.IPv6len + 2
		}
	}
	if len(packet) < offset {
		return nil, ErrBadRecord
	}
	return packet[offset:], nil
}

func clientOptionsName(options ClientOptions) string {
	if options.Version == Version6 {
		return "v6-" + options.Mode
	}
	return "v" + string(rune('0'+options.Version))
}

func testPSKFor(version int) string {
	if version == Version6 {
		return "test-password-v6"
	}
	return "test-password"
}

type pipeDialer struct {
	serve func(netproxy.Conn)
}

func (d *pipeDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	client, server := net.Pipe()
	go d.serve(server)
	return client, nil
}

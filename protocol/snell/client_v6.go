package snell

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type v6ClientConn struct {
	record      *v6RecordConn
	replyRead   atomic.Bool
	replyMu     sync.Mutex
	nonReusable bool
	pool        *v6Pool
	uses        int
	readEOF     atomic.Bool
	writeEOF    atomic.Bool
	closed      atomic.Bool
}

func (c *v6ClientConn) ensureReply() error {
	if c.replyRead.Load() {
		return nil
	}
	c.replyMu.Lock()
	defer c.replyMu.Unlock()
	if c.replyRead.Load() {
		return nil
	}
	if err := readReply(c.record); err != nil {
		return err
	}
	c.replyRead.Store(true)
	return nil
}

func (c *v6ClientConn) Read(p []byte) (int, error) {
	if err := c.ensureReply(); err != nil {
		return 0, err
	}
	n, err := c.record.Read(p)
	if errors.Is(err, io.EOF) {
		c.readEOF.Store(true)
	}
	return n, err
}

func (c *v6ClientConn) Write(p []byte) (int, error) { return c.record.Write(p) }

func (c *v6ClientConn) CloseWrite() error {
	if c.writeEOF.CompareAndSwap(false, true) {
		return c.record.writeEOF()
	}
	return nil
}

func (c *v6ClientConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.nonReusable || c.pool == nil {
		return c.record.Close()
	}
	if !c.writeEOF.Load() {
		if err := c.CloseWrite(); err != nil {
			_ = c.record.Close()
			return err
		}
	}
	if !c.readEOF.Load() {
		return c.record.Close()
	}
	_ = c.record.SetDeadline(time.Time{})
	c.pool.put(c.record, c.uses)
	return nil
}

func (c *v6ClientConn) SetDeadline(t time.Time) error      { return c.record.SetDeadline(t) }
func (c *v6ClientConn) SetReadDeadline(t time.Time) error  { return c.record.SetReadDeadline(t) }
func (c *v6ClientConn) SetWriteDeadline(t time.Time) error { return c.record.SetWriteDeadline(t) }

type v6PacketConn struct {
	record  *v6RecordConn
	target  string
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func newV6PacketConn(record *v6RecordConn, userKey, target string) (*v6PacketConn, error) {
	if _, err := record.Write(makeUDPRequest(userKey)); err != nil {
		return nil, err
	}
	if err := readReply(record); err != nil {
		return nil, err
	}
	return &v6PacketConn{record: record, target: target}, nil
}

func (c *v6PacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *v6PacketConn) Write(p []byte) (int, error) { return c.WriteTo(p, c.target) }

func (c *v6PacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	record, err := c.record.readPacket()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	addr, payload, err := parseUDPResponse(record)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if len(payload) > len(p) {
		return 0, netip.AddrPort{}, io.ErrShortBuffer
	}
	return copy(p, payload), addr, nil
}

func (c *v6PacketConn) WriteTo(p []byte, addr string) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	destination, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	packet, err := appendUDPRequestLimit(p, destination, v6MaxPayload)
	if err != nil {
		return 0, err
	}
	if err := c.record.writePacket(packet); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *v6PacketConn) Close() error                       { return c.record.Close() }
func (c *v6PacketConn) SetDeadline(t time.Time) error      { return c.record.SetDeadline(t) }
func (c *v6PacketConn) SetReadDeadline(t time.Time) error  { return c.record.SetReadDeadline(t) }
func (c *v6PacketConn) SetWriteDeadline(t time.Time) error { return c.record.SetWriteDeadline(t) }

type v6PoolEntry struct {
	record *v6RecordConn
	uses   int
}

type v6Pool struct {
	mu      sync.Mutex
	entries []v6PoolEntry
	create  func(context.Context, string) (*v6RecordConn, error)
}

func (p *v6Pool) get(ctx context.Context, network string) (*v6RecordConn, int, error) {
	p.mu.Lock()
	if n := len(p.entries); n > 0 {
		entry := p.entries[n-1]
		p.entries = p.entries[:n-1]
		p.mu.Unlock()
		return entry.record, entry.uses + 1, nil
	}
	p.mu.Unlock()
	record, err := p.create(ctx, network)
	return record, 1, err
}

func (p *v6Pool) put(record *v6RecordConn, uses int) {
	if uses >= 2 {
		_ = record.Close()
		return
	}
	p.mu.Lock()
	if len(p.entries) >= 10 {
		p.mu.Unlock()
		_ = record.Close()
		return
	}
	p.entries = append(p.entries, v6PoolEntry{record: record, uses: uses})
	p.mu.Unlock()
}

var _ netproxy.Conn = (*v6ClientConn)(nil)
var _ netproxy.PacketConn = (*v6PacketConn)(nil)

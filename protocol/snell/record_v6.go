package snell

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

const v6MaxPayload = 0xffff

type v6Mode uint8

const (
	v6ModeDefault v6Mode = iota
	v6ModeUnshaped
	v6ModeUnsafeRaw
)

func parseV6Mode(mode string) (v6Mode, error) {
	switch mode {
	case "", "default":
		return v6ModeDefault, nil
	case "unshaped":
		return v6ModeUnshaped, nil
	case "unsafe-raw":
		return v6ModeUnsafeRaw, nil
	default:
		return 0, fmt.Errorf("snell: invalid version 6 mode %q", mode)
	}
}

type v6RecordConn struct {
	upstream netproxy.Conn
	reader   *v6RecordReader
	writer   *v6RecordWriter
}

func newV6RecordConn(upstream netproxy.Conn, psk []byte, mode v6Mode) *v6RecordConn {
	key := append([]byte(nil), psk...)
	var profile *v6Profile
	if mode == v6ModeDefault {
		profile = newV6Profile(key)
	}
	return &v6RecordConn{
		upstream: upstream,
		reader:   &v6RecordReader{upstream: upstream, psk: key, mode: mode, profile: profile},
		writer:   &v6RecordWriter{upstream: upstream, psk: key, mode: mode, profile: profile},
	}
}

func (c *v6RecordConn) Read(p []byte) (int, error)         { return c.reader.Read(p) }
func (c *v6RecordConn) Write(p []byte) (int, error)        { return c.writer.Write(p) }
func (c *v6RecordConn) Close() error                       { return c.upstream.Close() }
func (c *v6RecordConn) SetDeadline(t time.Time) error      { return c.upstream.SetDeadline(t) }
func (c *v6RecordConn) SetReadDeadline(t time.Time) error  { return c.upstream.SetReadDeadline(t) }
func (c *v6RecordConn) SetWriteDeadline(t time.Time) error { return c.upstream.SetWriteDeadline(t) }
func (c *v6RecordConn) readPacket() ([]byte, error)        { return c.reader.nextRecord() }
func (c *v6RecordConn) writePacket(p []byte) error         { return c.writer.writePacket(p) }
func (c *v6RecordConn) writeEOF() error                    { return c.writer.writeEOF() }

type v6RecordReader struct {
	upstream io.Reader
	psk      []byte
	mode     v6Mode
	profile  *v6Profile
	aead     cipher.AEAD
	nonce    [nonceLen]byte
	seq      uint32
	cache    []byte
	offset   int
	mu       sync.Mutex
}

func (r *v6RecordReader) initialize() error {
	if r.mode == v6ModeUnsafeRaw || r.aead != nil {
		return nil
	}
	var salt []byte
	if r.mode == v6ModeDefault {
		block := make([]byte, r.profile.saltBlockLen)
		if _, err := io.ReadFull(r.upstream, block); err != nil {
			return err
		}
		extracted := r.profile.extractSalt(block)
		salt = extracted[:]
	} else {
		salt = make([]byte, saltLen)
		if _, err := io.ReadFull(r.upstream, salt); err != nil {
			return err
		}
	}
	aead, err := newAEAD(r.psk, salt)
	if err != nil {
		return err
	}
	r.aead = aead
	return nil
}

func (r *v6RecordReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for r.offset == len(r.cache) {
		record, err := r.readRecordLocked()
		if err != nil {
			return 0, err
		}
		r.cache = record
		r.offset = 0
	}
	n := copy(p, r.cache[r.offset:])
	r.offset += n
	if r.offset == len(r.cache) {
		r.cache = nil
		r.offset = 0
	}
	return n, nil
}

func (r *v6RecordReader) nextRecord() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.offset < len(r.cache) {
		out := append([]byte(nil), r.cache[r.offset:]...)
		r.cache = nil
		r.offset = 0
		return out, nil
	}
	return r.readRecordLocked()
}

func (r *v6RecordReader) readRecordLocked() ([]byte, error) {
	if err := r.initialize(); err != nil {
		return nil, err
	}
	if r.mode == v6ModeUnsafeRaw {
		header := make([]byte, headerPlainLen)
		if _, err := io.ReadFull(r.upstream, header); err != nil {
			return nil, err
		}
		paddingLen, payloadLen, err := parseV6Header(header, true)
		if err != nil || paddingLen != 0 {
			return nil, ErrBadRecord
		}
		if payloadLen == 0 {
			return nil, io.EOF
		}
		payload := make([]byte, payloadLen)
		_, err = io.ReadFull(r.upstream, payload)
		return payload, err
	}
	var prefix []byte
	if r.mode == v6ModeDefault {
		prefix = make([]byte, r.profile.recordPrefixLen(r.seq))
		if _, err := io.ReadFull(r.upstream, prefix); err != nil {
			return nil, err
		}
	}
	headerCipher := make([]byte, headerCipherLen)
	if _, err := io.ReadFull(r.upstream, headerCipher); err != nil {
		return nil, err
	}
	header, err := r.aead.Open(nil, r.nonce[:], headerCipher, prefix)
	increaseNonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	paddingLen, payloadLen, err := parseV6Header(header, r.mode != v6ModeDefault)
	if err != nil {
		return nil, err
	}
	if r.mode == v6ModeUnshaped && paddingLen != 0 {
		return nil, ErrBadRecord
	}
	seq := r.seq
	r.seq++
	padding := make([]byte, paddingLen)
	if _, err := io.ReadFull(r.upstream, padding); err != nil {
		return nil, err
	}
	if payloadLen == 0 {
		return nil, io.EOF
	}
	payloadCipher := make([]byte, payloadLen+aeadTagLen)
	if _, err := io.ReadFull(r.upstream, payloadCipher); err != nil {
		return nil, err
	}
	if r.mode == v6ModeDefault {
		r.profile.mixPaddingPayload(seq, padding, payloadCipher)
	}
	payload, err := r.aead.Open(nil, r.nonce[:], payloadCipher, padding)
	increaseNonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	return payload, nil
}

type v6RecordWriter struct {
	upstream io.Writer
	psk      []byte
	mode     v6Mode
	profile  *v6Profile
	aead     cipher.AEAD
	nonce    [nonceLen]byte
	salt     []byte
	saltSent bool
	seq      uint32
	chunk    int
	lastUnix int64
	mu       sync.Mutex
}

func (w *v6RecordWriter) initialize() error {
	if w.mode == v6ModeUnsafeRaw || w.aead != nil {
		return nil
	}
	w.salt = make([]byte, saltLen)
	if _, err := rand.Read(w.salt); err != nil {
		return err
	}
	aead, err := newAEAD(w.psk, w.salt)
	if err != nil {
		return err
	}
	w.aead = aead
	return nil
}

func (w *v6RecordWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		limit := w.payloadLimitLocked()
		end := min(written+limit, len(p))
		if err := w.writeRecordLocked(p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (w *v6RecordWriter) writePacket(payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	limit := w.payloadLimitLocked()
	if len(payload) > limit {
		return ErrPayloadTooLarge
	}
	return w.writeRecordLocked(payload)
}

func (w *v6RecordWriter) writeEOF() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.mode == v6ModeDefault {
		_ = w.payloadLimitLocked()
	}
	return w.writeRecordLocked(nil)
}

func (w *v6RecordWriter) payloadLimitLocked() int {
	if w.mode != v6ModeDefault {
		return v6MaxPayload
	}
	now := time.Now().Unix()
	if w.lastUnix == 0 || now-w.lastUnix > int64(w.profile.idleResetSec) {
		w.chunk = w.profile.chunkInitial
	}
	if w.chunk == 0 {
		w.chunk = w.profile.chunkInitial
	}
	limit := w.profile.chunkPayloadLimit(w.seq, w.chunk)
	if w.seq == 0 {
		limit = min(limit, w.profile.firstRecordCap)
	}
	w.chunk = w.profile.nextChunkSize(w.chunk)
	w.lastUnix = now
	return max(1, min(limit, v6MaxPayload))
}

func (w *v6RecordWriter) writeRecordLocked(payload []byte) error {
	if len(payload) > v6MaxPayload {
		return ErrPayloadTooLarge
	}
	if err := w.initialize(); err != nil {
		return err
	}
	if w.mode == v6ModeUnsafeRaw {
		frame := make([]byte, headerPlainLen+len(payload))
		putV6Header(frame[:headerPlainLen], 0, len(payload))
		copy(frame[headerPlainLen:], payload)
		return writeFull(w.upstream, frame)
	}
	var prefix, saltBlock []byte
	if w.mode == v6ModeDefault {
		prefix = make([]byte, w.profile.recordPrefixLen(w.seq))
		w.profile.fillPadding(w.seq, prefix)
		if !w.saltSent {
			saltBlock = make([]byte, w.profile.saltBlockLen)
			w.profile.fillPadding(^uint32(0), saltBlock)
			w.profile.writeSaltBlock(w.salt, saltBlock)
		}
	} else if !w.saltSent {
		saltBlock = append([]byte(nil), w.salt...)
	}
	paddingLen := 0
	if w.mode == v6ModeDefault {
		saltPrefixLen := 0
		if len(saltBlock) > 0 {
			saltPrefixLen = len(saltBlock) - saltLen
		}
		paddingLen = w.profile.paddingLen(w.seq, len(payload), len(prefix), saltPrefixLen, len(saltBlock))
	}
	var header [headerPlainLen]byte
	putV6Header(header[:], paddingLen, len(payload))
	headerCipher := w.aead.Seal(nil, w.nonce[:], header[:], prefix)
	increaseNonce(w.nonce[:])
	padding := make([]byte, paddingLen)
	if w.mode == v6ModeDefault {
		w.profile.fillPadding(w.seq, padding)
	}
	frame := make([]byte, 0, len(saltBlock)+len(prefix)+len(headerCipher)+len(padding)+len(payload)+aeadTagLen)
	frame = append(frame, saltBlock...)
	frame = append(frame, prefix...)
	frame = append(frame, headerCipher...)
	frame = append(frame, padding...)
	if len(payload) > 0 {
		payloadCipher := w.aead.Seal(nil, w.nonce[:], payload, padding)
		increaseNonce(w.nonce[:])
		if w.mode == v6ModeDefault {
			w.profile.mixPaddingPayload(w.seq, padding, payloadCipher)
			copy(frame[len(saltBlock)+len(prefix)+len(headerCipher):], padding)
		}
		frame = append(frame, payloadCipher...)
	}
	w.saltSent = true
	w.seq++
	return writeFull(w.upstream, frame)
}

func parseV6Header(header []byte, requireZeroReserved bool) (int, int, error) {
	if len(header) != headerPlainLen || header[0] != headerVersion ||
		requireZeroReserved && (header[1] != 0 || header[2] != 0) {
		return 0, 0, ErrBadRecord
	}
	return int(binary.BigEndian.Uint16(header[3:5])), int(binary.BigEndian.Uint16(header[5:7])), nil
}

func putV6Header(header []byte, paddingLen, payloadLen int) {
	header[0] = headerVersion
	header[1] = 0
	header[2] = 0
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLen))
	binary.BigEndian.PutUint16(header[5:7], uint16(payloadLen))
}

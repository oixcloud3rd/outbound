package snell

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"lukechampine.com/blake3"
)

const (
	v4DynamicRecordMSS         = 1208
	v4RecordSizeBoostThreshold = 128 * 1024
	identityMagic              = "DLSNID01"
	identityLength             = 16
)

type v4RecordConn struct {
	upstream netproxy.Conn
	psk      []byte
	identity bool

	reader *v4RecordReader
	writer *v4RecordWriter
}

func newV4RecordConn(upstream netproxy.Conn, psk []byte, identity bool) *v4RecordConn {
	key := append([]byte(nil), psk...)
	return &v4RecordConn{
		upstream: upstream,
		psk:      key,
		identity: identity,
		reader:   &v4RecordReader{upstream: upstream, psk: key},
		writer:   &v4RecordWriter{upstream: upstream, psk: key, identity: identity},
	}
}

func (c *v4RecordConn) Read(p []byte) (int, error)         { return c.reader.Read(p) }
func (c *v4RecordConn) Write(p []byte) (int, error)        { return c.writer.Write(p) }
func (c *v4RecordConn) Close() error                       { return c.upstream.Close() }
func (c *v4RecordConn) SetDeadline(t time.Time) error      { return c.upstream.SetDeadline(t) }
func (c *v4RecordConn) SetReadDeadline(t time.Time) error  { return c.upstream.SetReadDeadline(t) }
func (c *v4RecordConn) SetWriteDeadline(t time.Time) error { return c.upstream.SetWriteDeadline(t) }

func (c *v4RecordConn) writePacket(payload []byte) error {
	return c.writer.writePacket(payload)
}

func (c *v4RecordConn) readPacket() ([]byte, error) {
	return c.reader.nextRecord()
}

func (c *v4RecordConn) writeEOF() error {
	return c.writer.writeRecord(nil, 0)
}

type v4RecordReader struct {
	upstream io.Reader
	psk      []byte
	aead     cipher.AEAD
	nonce    [nonceLen]byte
	cache    []byte
	offset   int
	mu       sync.Mutex
}

func (r *v4RecordReader) initialize() error {
	if r.aead != nil {
		return nil
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r.upstream, salt); err != nil {
		return err
	}
	aead, err := newAEAD(r.psk, salt)
	if err != nil {
		return err
	}
	r.aead = aead
	return nil
}

func (r *v4RecordReader) Read(p []byte) (int, error) {
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

func (r *v4RecordReader) nextRecord() ([]byte, error) {
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

func (r *v4RecordReader) readRecordLocked() ([]byte, error) {
	if err := r.initialize(); err != nil {
		return nil, err
	}
	headerCipher := make([]byte, headerCipherLen)
	if _, err := io.ReadFull(r.upstream, headerCipher); err != nil {
		return nil, err
	}
	header, err := r.aead.Open(nil, r.nonce[:], headerCipher, nil)
	increaseNonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	if len(header) != headerPlainLen || header[0] != headerVersion {
		return nil, ErrBadRecord
	}
	paddingLen := int(binary.BigEndian.Uint16(header[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(header[5:7]))
	if payloadLen > maxPayloadLen || (payloadLen == 0 && paddingLen != 0) {
		return nil, ErrBadRecord
	}
	if payloadLen == 0 {
		return nil, io.EOF
	}
	body := make([]byte, paddingLen+payloadLen+aeadTagLen)
	if _, err := io.ReadFull(r.upstream, body); err != nil {
		return nil, err
	}
	if paddingLen > 0 {
		shufflePadding(body, paddingLen, payloadLen+aeadTagLen)
	}
	plain, err := r.aead.Open(nil, r.nonce[:], body[paddingLen:], nil)
	increaseNonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	return plain, nil
}

type v4RecordWriter struct {
	upstream io.Writer
	psk      []byte
	identity bool
	aead     cipher.AEAD
	nonce    [nonceLen]byte
	seen     int
	mu       sync.Mutex
}

func (w *v4RecordWriter) initialize() error {
	if w.aead != nil {
		return nil
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := newAEAD(w.psk, salt)
	if err != nil {
		return err
	}
	prefix := make([]byte, 0, saltLen+len(identityMagic)+identityLength)
	prefix = append(prefix, salt...)
	if w.identity {
		hash := blake3.Sum512(w.psk)
		prefix = append(prefix, identityMagic...)
		prefix = append(prefix, hash[:identityLength]...)
	}
	if err := writeFull(w.upstream, prefix); err != nil {
		return err
	}
	w.aead = aead
	return nil
}

func (w *v4RecordWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		limit := w.maxPayload()
		end := min(written+limit, len(p))
		paddingLen := randomPaddingLen(end-written, aeadTagLen)
		if err := w.writeRecordLocked(p[written:end], paddingLen); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (w *v4RecordWriter) writePacket(payload []byte) error {
	if len(payload) > maxPayloadLen {
		return ErrPayloadTooLarge
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeRecordLocked(payload, randomPaddingLen(len(payload), aeadTagLen))
}

func (w *v4RecordWriter) writeRecord(payload []byte, paddingLen int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeRecordLocked(payload, paddingLen)
}

func (w *v4RecordWriter) maxPayload() int {
	if w.seen >= v4RecordSizeBoostThreshold {
		return maxPayloadLen
	}
	limit := v4DynamicRecordMSS - headerPlainLen - 2*aeadTagLen
	if limit <= 0 || limit > maxPayloadLen {
		return maxPayloadLen
	}
	return limit
}

func (w *v4RecordWriter) writeRecordLocked(payload []byte, paddingLen int) error {
	if len(payload) > maxPayloadLen || paddingLen > maxPayloadLen || (len(payload) == 0 && paddingLen != 0) {
		return ErrPayloadTooLarge
	}
	if err := w.initialize(); err != nil {
		return err
	}
	var header [headerPlainLen]byte
	header[0] = headerVersion
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLen))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))
	frame := w.aead.Seal(nil, w.nonce[:], header[:], nil)
	increaseNonce(w.nonce[:])
	if len(payload) > 0 {
		body := make([]byte, paddingLen, paddingLen+len(payload)+aeadTagLen)
		if paddingLen > 0 {
			if _, err := rand.Read(body); err != nil {
				return err
			}
		}
		body = w.aead.Seal(body, w.nonce[:], payload, nil)
		increaseNonce(w.nonce[:])
		if paddingLen > 0 {
			shufflePadding(body, paddingLen, len(payload)+aeadTagLen)
		}
		frame = append(frame, body...)
		w.seen += len(payload)
	}
	return writeFull(w.upstream, frame)
}

func randomPaddingLen(payloadLen, tagLen int) int {
	if payloadLen == 0 {
		return 0
	}
	maxPadding := v4DynamicRecordMSS - headerPlainLen - 2*tagLen - payloadLen
	if maxPadding <= 0 {
		return 0
	}
	if maxPadding > 512 {
		maxPadding = 512
	}
	var seed [2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return 1
	}
	return int(binary.BigEndian.Uint16(seed[:])%uint16(maxPadding)) + 1
}

func shufflePadding(block []byte, paddingLen, ciphertextLen int) {
	for offset := 0; offset < paddingLen && offset < ciphertextLen; offset += 2 {
		block[offset], block[paddingLen+offset] = block[paddingLen+offset], block[offset]
	}
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

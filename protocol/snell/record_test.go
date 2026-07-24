package snell

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"lukechampine.com/blake3"
)

func TestV4RecordRoundTrip(t *testing.T) {
	t.Parallel()
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	client := newV4RecordConn(left, []byte("test-password"), false)
	server := newV4RecordConn(right, []byte("test-password"), false)
	testRecordRoundTrip(t, client, server)
}

func TestV6RecordRoundTrip(t *testing.T) {
	t.Parallel()
	for _, testMode := range []v6Mode{v6ModeDefault, v6ModeUnshaped, v6ModeUnsafeRaw} {
		t.Run(testModeName(testMode), func(t *testing.T) {
			left, right := net.Pipe()
			t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
			client := newV6RecordConn(left, []byte("test-password"), testMode)
			server := newV6RecordConn(right, []byte("test-password"), testMode)
			testRecordRoundTrip(t, client, server)
		})
	}
}

type recordConn interface {
	io.Reader
	io.Writer
}

func testRecordRoundTrip(t *testing.T, client, server recordConn) {
	t.Helper()
	payload := bytes.Repeat([]byte("snell-record-"), 4096)
	errChannel := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		errChannel <- err
	}()
	received := make([]byte, len(payload))
	_, err := io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, payload, received)
	require.NoError(t, <-errChannel)

	response := bytes.Repeat([]byte("response-"), 2048)
	go func() {
		_, err := server.Write(response)
		errChannel <- err
	}()
	received = make([]byte, len(response))
	_, err = io.ReadFull(client, received)
	require.NoError(t, err)
	require.Equal(t, response, received)
	require.NoError(t, <-errChannel)
}

func TestV4IdentityPrefix(t *testing.T) {
	t.Parallel()
	recorder := &recordingConn{}
	password := []byte("identity-password")
	conn := newV4RecordConn(recorder, password, true)
	_, err := conn.Write([]byte("payload"))
	require.NoError(t, err)
	_, err = conn.Write([]byte("second-record"))
	require.NoError(t, err)
	wire := recorder.Bytes()
	require.GreaterOrEqual(t, len(wire), saltLen+len(identityMagic)+identityLength)
	require.Equal(t, identityMagic, string(wire[saltLen:saltLen+len(identityMagic)]))
	hash := blake3.Sum512(password)
	require.Equal(t, hash[:identityLength], wire[saltLen+len(identityMagic):saltLen+len(identityMagic)+identityLength])
	require.Equal(t, 1, bytes.Count(wire, []byte(identityMagic)))
}

func TestV4IdentityConcurrentInitialization(t *testing.T) {
	t.Parallel()
	recorder := &recordingConn{}
	conn := newV4RecordConn(recorder, []byte("identity-password"), true)
	const writers = 8
	errors := make(chan error, writers)
	var waitGroup sync.WaitGroup
	for index := 0; index < writers; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, err := conn.Write([]byte("concurrent-record"))
			errors <- err
		}()
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.Equal(t, 1, bytes.Count(recorder.Bytes(), []byte(identityMagic)))
}

func TestV6DefaultHeaderAllowsReservedBytes(t *testing.T) {
	t.Parallel()
	header := []byte{headerVersion, 1, 2, 0, 0, 0, 1}
	paddingLen, payloadLen, err := parseV6Header(header, false)
	require.NoError(t, err)
	require.Zero(t, paddingLen)
	require.Equal(t, 1, payloadLen)
	_, _, err = parseV6Header(header, true)
	require.ErrorIs(t, err, ErrBadRecord)
}

func testModeName(mode v6Mode) string {
	switch mode {
	case v6ModeDefault:
		return "default"
	case v6ModeUnshaped:
		return "unshaped"
	default:
		return "unsafe-raw"
	}
}

type recordingConn struct {
	bytes.Buffer
	mu sync.Mutex
}

func (c *recordingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Buffer.Write(p)
}
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

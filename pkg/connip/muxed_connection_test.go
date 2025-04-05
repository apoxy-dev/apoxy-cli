package connip_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy-cli/pkg/connip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockConnection struct {
	mock.Mock
	closed bool
}

func (m *MockConnection) ReadPacket(p []byte) (int, error) {
	if m.closed {
		return 0, net.ErrClosed
	}

	args := m.Called(p)
	n := args.Int(0)
	copy(p, args.Get(1).([]byte))
	return n, args.Error(2)
}

func (m *MockConnection) WritePacket(p []byte) ([]byte, error) {
	args := m.Called(p)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockConnection) Close() error {
	m.closed = true
	return m.Called().Error(0)
}

func TestMuxedConnection(t *testing.T) {
	t.Run("Add and Remove Connection", func(t *testing.T) {
		mux := connip.NewMuxedConnection()
		mockConn := new(MockConnection)
		mockConn.On("ReadPacket", mock.Anything).Return(0, []byte{}, nil).Maybe()
		mockConn.On("Close").Return(nil).Once()

		prefix := netip.MustParsePrefix("2001:db8::/96")
		mux.AddConnection(prefix, mockConn)
		err := mux.RemoveConnection(prefix)
		assert.NoError(t, err)

		// Try removing again should fail
		err = mux.RemoveConnection(prefix)
		assert.Error(t, err)
	})

	t.Run("Remove Connection - Invalid Prefix", func(t *testing.T) {
		mux := connip.NewMuxedConnection()
		prefix := netip.MustParsePrefix("192.0.2.0/24")
		err := mux.RemoveConnection(prefix)
		assert.Error(t, err)
	})

	t.Run("WritePacket - Success", func(t *testing.T) {
		mux := connip.NewMuxedConnection()
		mockConn := new(MockConnection)
		mockConn.On("ReadPacket", mock.Anything).Return(0, []byte{}, nil).Maybe()

		prefix := netip.MustParsePrefix("2001:db8::/96")
		mux.AddConnection(prefix, mockConn)

		pkt := make([]byte, 40)
		pkt[0] = 0x60 // IPv6
		copy(pkt[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())

		mockConn.On("WritePacket", pkt).Return([]byte("ok"), nil).Once()

		resp, err := mux.WritePacket(pkt)
		assert.NoError(t, err)
		assert.Equal(t, []byte("ok"), resp)
		mockConn.AssertExpectations(t)
	})

	t.Run("WritePacket - No Connection Found", func(t *testing.T) {
		mux := connip.NewMuxedConnection()

		pkt := make([]byte, 40)
		pkt[0] = 0x60
		copy(pkt[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())

		resp, err := mux.WritePacket(pkt)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "no matching tunnel")
	})

	t.Run("ReadPacket - Success", func(t *testing.T) {
		mux := connip.NewMuxedConnection()
		mockConn := new(MockConnection)

		expected := []byte("hello")
		mockConn.On("ReadPacket", mock.Anything).Return(len(expected), expected, nil)

		prefix := netip.MustParsePrefix("2001:db8::/96")
		mux.AddConnection(prefix, mockConn)

		time.Sleep(10 * time.Millisecond) // let goroutine read once

		buf := make([]byte, 1500)
		n, err := mux.ReadPacket(buf)
		assert.NoError(t, err)
		assert.Equal(t, len(expected), n)
		assert.Equal(t, expected, buf[:n])
		mockConn.AssertExpectations(t)
	})

	t.Run("ReadPacket - Closed Channel", func(t *testing.T) {
		mux := connip.NewMuxedConnection()
		_ = mux.Close()

		buf := make([]byte, 1500)
		_, err := mux.ReadPacket(buf)

		assert.ErrorIs(t, err, net.ErrClosed)
	})

	t.Run("Close - All Connections", func(t *testing.T) {
		mux := connip.NewMuxedConnection()
		mockConn := new(MockConnection)
		mockConn.On("ReadPacket", mock.Anything).Return(0, []byte{}, nil).Maybe()
		mockConn.On("Close").Return(nil).Once()

		prefix := netip.MustParsePrefix("2001:db8::/96")
		mux.AddConnection(prefix, mockConn)

		err := mux.Close()
		assert.NoError(t, err)
		mockConn.AssertExpectations(t)
	})
}

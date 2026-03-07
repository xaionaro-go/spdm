package requester

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/status"
	"github.com/xaionaro-go/spdm/pkg/session"
)

func newTestRequester() *Requester {
	return New(Config{
		Transport: &mockTransport{},
	})
}

func TestHeartbeat_NoSession(t *testing.T) {
	r := newTestRequester()
	err := r.Heartbeat(context.Background(), 0x12345678)
	assert.Error(t, err)
	assert.ErrorIs(t, err, status.ErrInvalidParameter)
}

func TestHeartbeat_SessionNotEstablished(t *testing.T) {
	r := newTestRequester()
	sid := session.SessionID(0xAABBCCDD)
	r.sessions[sid] = session.NewSession(sid, algo.Version(0x12), algo.HashSHA256, algo.AEADAES128GCM, true)
	// NewSession starts in StateHandshake, not StateEstablished.
	err := r.Heartbeat(context.Background(), sid)
	assert.Error(t, err)
	assert.ErrorIs(t, err, status.ErrInvalidStateLocal)
}

func TestKeyUpdate_NoSession(t *testing.T) {
	r := newTestRequester()
	err := r.KeyUpdate(context.Background(), 0x12345678, 1)
	assert.Error(t, err)
	assert.ErrorIs(t, err, status.ErrInvalidParameter)
}

func TestKeyUpdate_SessionNotEstablished(t *testing.T) {
	r := newTestRequester()
	sid := session.SessionID(0xAABBCCDD)
	r.sessions[sid] = session.NewSession(sid, algo.Version(0x12), algo.HashSHA256, algo.AEADAES128GCM, true)
	err := r.KeyUpdate(context.Background(), sid, 1)
	assert.Error(t, err)
	assert.ErrorIs(t, err, status.ErrInvalidStateLocal)
}

func TestKeyUpdate_InvalidOperation(t *testing.T) {
	r := newTestRequester()
	err := r.KeyUpdate(context.Background(), 0x12345678, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid operation")

	err = r.KeyUpdate(context.Background(), 0x12345678, 4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid operation")
}

func TestEndSession_NoSession(t *testing.T) {
	r := newTestRequester()
	err := r.EndSession(context.Background(), 0x12345678)
	assert.Error(t, err)
	assert.ErrorIs(t, err, status.ErrInvalidParameter)
}

func TestEndSession_SessionNotEstablished(t *testing.T) {
	r := newTestRequester()
	sid := session.SessionID(0xAABBCCDD)
	r.sessions[sid] = session.NewSession(sid, algo.Version(0x12), algo.HashSHA256, algo.AEADAES128GCM, true)
	err := r.EndSession(context.Background(), sid)
	assert.Error(t, err)
	assert.ErrorIs(t, err, status.ErrInvalidStateLocal)
}

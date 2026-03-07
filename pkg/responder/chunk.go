package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// chunkSendState tracks the reassembly of a large message sent via CHUNK_SEND.
type chunkSendState struct {
	handle           uint8
	expectedSeqNo    uint16
	largeMessageSize uint32
	buffer           []byte
}

// chunkGetState tracks the sending of a large response via CHUNK_GET.
type chunkGetState struct {
	handle        uint8
	largeMessage  []byte
	offset        int
	expectedSeqNo uint16
}

func (r *Responder) handleChunkSend(ctx context.Context, request []byte) ([]byte, error) {
	var req msgs.ChunkSend
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	handle := req.Header.Param2

	if req.ChunkSeqNo == 0 {
		// Start of a new chunked transfer.
		r.chunkSend = &chunkSendState{
			handle:           handle,
			expectedSeqNo:    0,
			largeMessageSize: req.LargeMessageSize,
			buffer:           make([]byte, 0, req.LargeMessageSize),
		}
	}

	if r.chunkSend == nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	if req.ChunkSeqNo != r.chunkSend.expectedSeqNo {
		r.chunkSend = nil
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	r.chunkSend.buffer = append(r.chunkSend.buffer, req.Chunk...)
	r.chunkSend.expectedSeqNo++

	ack := &msgs.ChunkSendAck{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseChunkSendAck),
			Param2:              handle,
		}},
		ChunkSeqNo: req.ChunkSeqNo,
	}

	if req.IsLastChunk() {
		// Reassembly complete: process the reassembled message.
		reassembled := r.chunkSend.buffer
		r.chunkSend = nil

		logger.Debugf(ctx, "handleChunkSend: reassembled %d bytes, processing", len(reassembled))

		// Process the reassembled large message.
		innerResp, err := r.ProcessMessage(ctx, reassembled)
		if err != nil {
			return nil, err
		}

		// If the response is too large, store it for CHUNK_GET retrieval.
		if uint32(len(innerResp)) > r.cfg.DataTransferSize {
			r.chunkGet = &chunkGetState{
				handle:       handle,
				largeMessage: innerResp,
			}
			// Return the ACK with early error = LARGE_RESPONSE to signal
			// that the requester should use CHUNK_GET.
			ack.Header.Param1 = msgs.ChunkSendAckAttrEarlyError
			ack.Response = r.buildError(codes.ErrorLargeResponse, handle)
		} else {
			// Response fits in a single message; embed it in the final ACK.
			ack.Response = innerResp
		}
	}

	logger.Debugf(ctx, "handleChunkSend: seq=%d last=%v bufLen=%d", req.ChunkSeqNo, req.IsLastChunk(), len(r.chunkSend.getBuffer()))
	return ack.Marshal()
}

func (r *Responder) handleChunkGet(ctx context.Context, request []byte) ([]byte, error) {
	var req msgs.ChunkGet
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	if r.chunkGet == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	if req.ChunkSeqNo != r.chunkGet.expectedSeqNo {
		r.chunkGet = nil
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	handle := req.Header.Param2
	data := r.chunkGet.largeMessage
	offset := r.chunkGet.offset

	// Maximum chunk payload: DataTransferSize minus CHUNK_RESPONSE header overhead.
	// Header: 4 (msg header) + 8 (seqno+reserved+chunksize) = 12 bytes.
	// First chunk also includes 4 bytes for LargeMessageSize.
	overhead := 12
	if req.ChunkSeqNo == 0 {
		overhead = 16
	}
	maxChunk := int(r.cfg.DataTransferSize) - overhead
	if maxChunk <= 0 {
		r.chunkGet = nil
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	end := offset + maxChunk
	if end > len(data) {
		end = len(data)
	}

	chunk := data[offset:end]
	isLast := end >= len(data)

	var attrs uint8
	if isLast {
		attrs = msgs.ChunkResponseAttrLastChunk
	}

	resp := &msgs.ChunkResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseChunkResponse),
			Param1:              attrs,
			Param2:              handle,
		}},
		ChunkSeqNo: req.ChunkSeqNo,
		ChunkSize:  uint32(len(chunk)),
		Chunk:      chunk,
	}
	if req.ChunkSeqNo == 0 {
		resp.LargeMessageSize = uint32(len(data))
	}

	r.chunkGet.offset = end
	r.chunkGet.expectedSeqNo++

	if isLast {
		r.chunkGet = nil
	}

	logger.Debugf(ctx, "handleChunkGet: seq=%d chunkLen=%d last=%v", req.ChunkSeqNo, len(chunk), isLast)
	return resp.Marshal()
}

// getBuffer returns the current buffer or nil if chunkSend is nil. Used for logging.
func (s *chunkSendState) getBuffer() []byte {
	if s == nil {
		return nil
	}
	return s.buffer
}

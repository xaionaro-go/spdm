package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// ChunkSend splits a large SPDM message into chunks and sends them via
// CHUNK_SEND per DSP0274 Section 10.20. The handle identifies the request
// being chunked.
func (r *Requester) ChunkSend(ctx context.Context, handle uint8, largeMsg []byte) error {
	logger.Debugf(ctx, "ChunkSend: handle=%d totalSize=%d", handle, len(largeMsg))

	ver := uint8(r.conn.PeerVersion)
	// Maximum chunk payload per message: DataTransferSize minus CHUNK_SEND header overhead.
	// CHUNK_SEND header: 4 (msg header) + 8 (seqno+reserved+chunksize) = 12 bytes.
	// First chunk also includes 4 bytes for LargeMessageSize.
	maxChunkFirst := int(r.cfg.DataTransferSize) - 16
	maxChunkRest := int(r.cfg.DataTransferSize) - 12

	if maxChunkFirst <= 0 || maxChunkRest <= 0 {
		return &ErrChunkDataTransferSizeTooSmall{}
	}

	offset := 0
	seqNo := uint16(0)
	totalSize := len(largeMsg)

	for offset < totalSize {
		maxChunk := maxChunkRest
		if seqNo == 0 {
			maxChunk = maxChunkFirst
		}

		end := offset + maxChunk
		if end > totalSize {
			end = totalSize
		}
		chunk := largeMsg[offset:end]
		isLast := end >= totalSize

		var attrs uint8
		if isLast {
			attrs = msgs.ChunkSendAttrLastChunk
		}

		req := &msgs.ChunkSend{
			Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
				SPDMVersion:         ver,
				RequestResponseCode: uint8(codes.RequestChunkSend),
				Param1:              attrs,
				Param2:              handle,
			}},
			ChunkSeqNo: seqNo,
			ChunkSize:  uint32(len(chunk)),
			Chunk:      chunk,
		}
		if seqNo == 0 {
			req.LargeMessageSize = uint32(totalSize)
		}

		resp, err := r.sendReceive(ctx, req)
		if err != nil {
			return &ErrChunkSend{SeqNo: seqNo, Err: err}
		}

		if resp[1] != uint8(codes.ResponseChunkSendAck) {
			return &ErrChunkSendUnexpectedResponseCode{Code: resp[1], SeqNo: seqNo}
		}

		var ack msgs.ChunkSendAck
		if err := ack.Unmarshal(resp); err != nil {
			return &ErrChunkUnmarshalAck{Err: err}
		}

		// Check for early error response embedded in ACK.
		if ack.Header.Param1&msgs.ChunkSendAckAttrEarlyError != 0 {
			return &ErrChunkSendEarlyError{SeqNo: seqNo}
		}

		offset = end
		seqNo++
	}

	logger.Debugf(ctx, "ChunkSend: completed %d chunks", seqNo)
	return nil
}

// ChunkGet reassembles a large SPDM response via CHUNK_GET per DSP0274 Section 10.21.
func (r *Requester) ChunkGet(ctx context.Context, handle uint8) ([]byte, error) {
	logger.Debugf(ctx, "ChunkGet: handle=%d", handle)

	ver := uint8(r.conn.PeerVersion)
	var result []byte
	seqNo := uint16(0)

	for {
		req := &msgs.ChunkGet{
			Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
				SPDMVersion:         ver,
				RequestResponseCode: uint8(codes.RequestChunkGet),
				Param2:              handle,
			}},
			ChunkSeqNo: seqNo,
		}

		resp, err := r.sendReceive(ctx, req)
		if err != nil {
			return nil, &ErrChunkGet{SeqNo: seqNo, Err: err}
		}

		if resp[1] != uint8(codes.ResponseChunkResponse) {
			return nil, &ErrChunkGetUnexpectedResponseCode{Code: resp[1], SeqNo: seqNo}
		}

		var cr msgs.ChunkResponse
		if err := cr.Unmarshal(resp); err != nil {
			return nil, &ErrChunkUnmarshalResponse{Err: err}
		}

		result = append(result, cr.Chunk...)

		if cr.IsLastChunk() {
			break
		}
		seqNo++
	}

	logger.Debugf(ctx, "ChunkGet: reassembled %d bytes over %d chunks", len(result), seqNo+1)
	return result, nil
}

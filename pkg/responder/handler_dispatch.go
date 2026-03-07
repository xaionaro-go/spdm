package responder

import (
	"context"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
)

// messageHandler is the signature for request handler methods on Responder.
type messageHandler func(*Responder, context.Context, []byte) ([]byte, error)

// messageHandlers maps each SPDM request code to its handler method.
// Populated in init() to avoid an initialization cycle with handleChunkSend,
// which calls ProcessMessage (which references this map).
var messageHandlers map[codes.RequestCode]messageHandler

func init() {
	messageHandlers = map[codes.RequestCode]messageHandler{
		codes.RequestGetVersion:                  (*Responder).handleGetVersion,
		codes.RequestGetCapabilities:             (*Responder).handleGetCapabilities,
		codes.RequestNegotiateAlgorithms:         (*Responder).handleNegotiateAlgorithms,
		codes.RequestGetDigests:                  (*Responder).handleGetDigests,
		codes.RequestGetCertificate:              (*Responder).handleGetCertificate,
		codes.RequestChallenge:                   (*Responder).handleChallenge,
		codes.RequestGetMeasurements:             (*Responder).handleGetMeasurements,
		codes.RequestKeyExchange:                 (*Responder).handleKeyExchange,
		codes.RequestFinish:                      (*Responder).handleFinish,
		codes.RequestPSKExchange:                 (*Responder).handlePSKExchange,
		codes.RequestPSKFinish:                   (*Responder).handlePSKFinish,
		codes.RequestHeartbeat:                   (*Responder).handleHeartbeat,
		codes.RequestKeyUpdate:                   (*Responder).handleKeyUpdate,
		codes.RequestEndSession:                  (*Responder).handleEndSession,
		codes.RequestVendorDefined:               (*Responder).handleVendorDefined,
		codes.RequestGetCSR:                      (*Responder).handleGetCSR,
		codes.RequestSetCertificate:              (*Responder).handleSetCertificate,
		codes.RequestGetKeyPairInfo:              (*Responder).handleGetKeyPairInfo,
		codes.RequestGetEndpointInfo:             (*Responder).handleGetEndpointInfo,
		codes.RequestGetMeasurementExtensionLog:  (*Responder).handleGetMEL,
		codes.RequestChunkSend:                   (*Responder).handleChunkSend,
		codes.RequestChunkGet:                    (*Responder).handleChunkGet,
		codes.RequestSetKeyPairInfo:              (*Responder).handleSetKeyPairInfo,
		codes.RequestRespondIfReady:              (*Responder).handleRespondIfReady,
		codes.RequestGetEncapsulatedRequest:      (*Responder).handleGetEncapsulatedRequest,
		codes.RequestDeliverEncapsulatedResponse: (*Responder).handleDeliverEncapsulatedResponse,
		codes.RequestGetSupportedEventTypes:      (*Responder).handleGetSupportedEventTypes,
		codes.RequestSubscribeEventTypes:         (*Responder).handleSubscribeEventTypes,
		codes.RequestSendEvent:                   (*Responder).handleSendEvent,
	}
}

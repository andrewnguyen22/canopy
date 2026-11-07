package contract

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	MessageObserveEnclaveName        = "takusenObserveEnclave"
	MessageRevokeEnclaveName         = "takusenRevokeEnclave"
	MessageRegisterServicerName      = "takusenRegisterServicer"
	MessageUpdateServicerName        = "takusenUpdateServicer"
	MessageObserveAuthorizationName  = "takusenObserveAuthorization"
	MessageSubmitExecutionName       = "takusenSubmitExecution"
	MessageReassignRequestName       = "takusenReassignRequest"
	MessageFinalizeRequestName       = "takusenFinalizeRequest"
	MessageSubmitQuorumSignatureName = "takusenSubmitQuorumSignature"
)

var ContractConfig = &PluginConfig{
	Name:    "takusen",
	Id:      22,
	Version: 1,
	SupportedTransactions: []string{
		MessageObserveEnclaveName,
		MessageRevokeEnclaveName,
		MessageRegisterServicerName,
		MessageUpdateServicerName,
		MessageObserveAuthorizationName,
		MessageSubmitExecutionName,
		MessageReassignRequestName,
		MessageFinalizeRequestName,
		MessageSubmitQuorumSignatureName,
	},
	TransactionTypeUrls: []string{
		"type.googleapis.com/types.MessageObserveEnclave",
		"type.googleapis.com/types.MessageRevokeEnclave",
		"type.googleapis.com/types.MessageRegisterServicer",
		"type.googleapis.com/types.MessageUpdateServicer",
		"type.googleapis.com/types.MessageObserveAuthorization",
		"type.googleapis.com/types.MessageSubmitExecution",
		"type.googleapis.com/types.MessageReassignRequest",
		"type.googleapis.com/types.MessageFinalizeRequest",
		"type.googleapis.com/types.MessageSubmitQuorumSignature",
	},
	CustomStatePrefixes: [][]byte{
		enclavePrefix, servicerPrefix, requestPrefix, executionPrefix,
		settlementPrefix, observationPrefix, blockAnchorPrefix,
		quorumProofPrefix, quorumSharePrefix,
	},
}

func init() {
	file_account_proto_init()
	file_event_proto_init()
	file_plugin_proto_init()
	file_tx_proto_init()
	for _, file := range []protoreflect.FileDescriptor{
		anypb.File_google_protobuf_any_proto,
		File_account_proto, File_event_proto, File_plugin_proto, File_tx_proto,
	} {
		fd, _ := proto.Marshal(protodesc.ToFileDescriptorProto(file))
		ContractConfig.FileDescriptorProtos = append(ContractConfig.FileDescriptorProtos, fd)
	}
}

type Contract struct {
	Config    Config
	FSMConfig *PluginFSMConfig
	plugin    *Plugin
	fsmId     uint64
}

func (c *Contract) Genesis(_ *PluginGenesisRequest) *PluginGenesisResponse {
	return &PluginGenesisResponse{}
}

func (c *Contract) BeginBlock(request *PluginBeginRequest) *PluginBeginResponse {
	anchor := &BlockAnchor{Height: request.Height, PreviousBlockHash: request.PreviousBlockHash}
	encoded, err := Marshal(anchor)
	if err != nil {
		return &PluginBeginResponse{Error: err}
	}
	response, err := c.plugin.StateWrite(c, &PluginStateWriteRequest{Sets: []*PluginSetOp{{Key: KeyForBlockAnchor(), Value: encoded}}})
	if err != nil {
		return &PluginBeginResponse{Error: err}
	}
	return &PluginBeginResponse{Error: response.Error}
}

func (c *Contract) EndBlock(_ *PluginEndRequest) *PluginEndResponse {
	return &PluginEndResponse{}
}

func (c *Contract) CheckTx(request *PluginCheckRequest) *PluginCheckResponse {
	if request.Tx == nil || request.Tx.Fee != 0 {
		return &PluginCheckResponse{Error: ErrInvalidTransaction("Takusen transactions currently require a zero fee")}
	}
	message, err := FromAny(request.Tx.Msg)
	if err != nil {
		return &PluginCheckResponse{Error: err}
	}
	var signer []byte
	switch message := message.(type) {
	case *MessageObserveEnclave:
		signer, err = checkObserveEnclave(message)
	case *MessageRevokeEnclave:
		signer, err = checkRevokeEnclave(message)
	case *MessageRegisterServicer:
		signer, err = checkRegisterServicer(message)
	case *MessageUpdateServicer:
		signer, err = checkUpdateServicer(message)
	case *MessageObserveAuthorization:
		signer, err = checkObserveAuthorization(message)
	case *MessageSubmitExecution:
		signer, err = checkSubmitExecution(message)
	case *MessageReassignRequest:
		signer, err = checkReassignRequest(message)
	case *MessageFinalizeRequest:
		signer, err = checkFinalizeRequest(message)
	case *MessageSubmitQuorumSignature:
		signer, err = checkSubmitQuorumSignature(message)
	default:
		return &PluginCheckResponse{Error: ErrInvalidMessageCast()}
	}
	if err != nil {
		return &PluginCheckResponse{Error: err}
	}
	return &PluginCheckResponse{AuthorizedSigners: [][]byte{signer}}
}

func (c *Contract) DeliverTx(request *PluginDeliverRequest) *PluginDeliverResponse {
	message, err := FromAny(request.Tx.Msg)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	switch message := message.(type) {
	case *MessageObserveEnclave:
		return c.deliverObserveEnclave(request.Height, message)
	case *MessageRevokeEnclave:
		return c.deliverRevokeEnclave(request.Height, message)
	case *MessageRegisterServicer:
		return c.deliverRegisterServicer(request.Height, message)
	case *MessageUpdateServicer:
		return c.deliverUpdateServicer(message)
	case *MessageObserveAuthorization:
		return c.deliverObserveAuthorization(request.Height, message)
	case *MessageSubmitExecution:
		return c.deliverSubmitExecution(request.Height, message)
	case *MessageReassignRequest:
		return c.deliverReassignRequest(request.Height, message)
	case *MessageFinalizeRequest:
		return c.deliverFinalizeRequest(request.Height, message)
	case *MessageSubmitQuorumSignature:
		return c.deliverSubmitQuorumSignature(request.Height, message)
	default:
		return &PluginDeliverResponse{Error: ErrInvalidMessageCast()}
	}
}

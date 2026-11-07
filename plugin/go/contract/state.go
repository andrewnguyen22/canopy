package contract

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"google.golang.org/protobuf/proto"
)

var (
	accountPrefix     = []byte{1}
	poolPrefix        = []byte{2}
	validatorPrefix   = []byte{3}
	enclavePrefix     = []byte{100}
	servicerPrefix    = []byte{101}
	requestPrefix     = []byte{102}
	executionPrefix   = []byte{103}
	settlementPrefix  = []byte{104}
	observationPrefix = []byte{105}
	blockAnchorPrefix = []byte{106}
	quorumProofPrefix = []byte{107}
	quorumSharePrefix = []byte{108}
)

func EnclavePrefix() []byte     { return JoinLenPrefix(enclavePrefix) }
func ServicerPrefix() []byte    { return JoinLenPrefix(servicerPrefix) }
func RequestPrefix() []byte     { return JoinLenPrefix(requestPrefix) }
func SettlementPrefix() []byte  { return JoinLenPrefix(settlementPrefix) }
func QuorumProofPrefix() []byte { return JoinLenPrefix(quorumProofPrefix) }

func KeyForAccount(address []byte) []byte   { return JoinLenPrefix(accountPrefix, address) }
func KeyForValidator(address []byte) []byte { return JoinLenPrefix(validatorPrefix, address) }
func ValidatorPrefix() []byte               { return JoinLenPrefix(validatorPrefix) }
func KeyForFeePool(chainID uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, chainID)
	return JoinLenPrefix(poolPrefix, encoded)
}
func KeyForEnclave(keyID string) []byte     { return JoinLenPrefix(enclavePrefix, []byte(keyID)) }
func KeyForServicer(address []byte) []byte  { return JoinLenPrefix(servicerPrefix, address) }
func KeyForRequest(requestID string) []byte { return JoinLenPrefix(requestPrefix, []byte(requestID)) }
func KeyForExecution(executionID string) []byte {
	return JoinLenPrefix(executionPrefix, []byte(executionID))
}
func KeyForSettlement(requestID string) []byte {
	return JoinLenPrefix(settlementPrefix, []byte(requestID))
}
func KeyForObservation(kind byte, subjectHash, observer []byte) []byte {
	return JoinLenPrefix(observationPrefix, []byte{kind}, subjectHash, observer)
}
func ObservationSubjectPrefix(kind byte, subjectHash []byte) []byte {
	return JoinLenPrefix(observationPrefix, []byte{kind}, subjectHash)
}
func KeyForBlockAnchor() []byte { return JoinLenPrefix(blockAnchorPrefix) }
func KeyForQuorumProof(proofID []byte) []byte {
	return JoinLenPrefix(quorumProofPrefix, proofID)
}
func KeyForQuorumShare(proofID, observer []byte) []byte {
	return JoinLenPrefix(quorumSharePrefix, proofID, observer)
}
func QuorumShareProofPrefix(proofID []byte) []byte {
	return JoinLenPrefix(quorumSharePrefix, proofID)
}

func (c *Contract) read(key []byte, destination proto.Message) (bool, *PluginError) {
	response, err := c.plugin.StateRead(c, &PluginStateReadRequest{Keys: []*PluginKeyRead{{QueryId: 1, Key: key}}})
	if err != nil {
		return false, err
	}
	if response.Error != nil {
		return false, response.Error
	}
	if len(response.Results) != 1 || len(response.Results[0].Entries) == 0 || len(response.Results[0].Entries[0].Value) == 0 {
		return false, nil
	}
	if err = Unmarshal(response.Results[0].Entries[0].Value, destination); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Contract) rangeRead(prefix []byte) ([]*PluginStateEntry, *PluginError) {
	response, err := c.plugin.StateRead(c, &PluginStateReadRequest{Ranges: []*PluginRangeRead{{QueryId: 1, Prefix: prefix, Limit: 5000}}})
	if err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, response.Error
	}
	if len(response.Results) != 1 {
		return nil, ErrState("unexpected range response")
	}
	return response.Results[0].Entries, nil
}

func (c *Contract) write(records map[string]proto.Message) *PluginError {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	request := &PluginStateWriteRequest{}
	for _, key := range keys {
		encoded, err := Marshal(records[key])
		if err != nil {
			return err
		}
		request.Sets = append(request.Sets, &PluginSetOp{Key: []byte(key), Value: encoded})
	}
	response, err := c.plugin.StateWrite(c, request)
	if err != nil {
		return err
	}
	return response.Error
}

func hashFields(fields ...[]byte) []byte {
	h := sha256.New()
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(field)
	}
	return h.Sum(nil)
}

func uint64Bytes(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}

func uint32Bytes(value uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, value)
	return result
}

func stringListBytes(values []string) []byte {
	fields := make([][]byte, len(values))
	for index := range values {
		fields[index] = []byte(values[index])
	}
	return hashFields(fields...)
}

package contract

import (
	"bytes"
	"encoding/hex"
	"math/big"
)

const (
	observationEnclave       byte = 1
	observationAuthorization byte = 2
	observationSettlement    byte = 3
	observationReassignment  byte = 4
	observationRevocation    byte = 5
)

func enclaveSubject(message *MessageObserveEnclave) []byte {
	return hashFields(
		[]byte("takusen:enclave-registration"), message.OwnerAddress, []byte(message.TeeKeyId),
		message.PublicKey, message.AttestationHash, message.Pcr0, message.Pcr1, message.Pcr2,
		message.Nonce, message.UserData, message.ProofSignature,
	)
}

func revocationSubject(message *MessageRevokeEnclave) []byte {
	return hashFields([]byte("takusen:enclave-revocation"), []byte(message.TeeKeyId))
}

func authorizationSubject(message *MessageObserveAuthorization) []byte {
	return hashFields(
		[]byte("takusen:base-authorization"), []byte(message.RequestId), message.InputHash,
		message.Requester, uint64Bytes(message.ReservedBudget), []byte(message.OutputType),
		stringListBytes(message.Models), uint32Bytes(message.ExecutionQuorum), message.BaseTxHash,
		uint64Bytes(message.DeadlineHeight),
	)
}

func settlementSubject(message *MessageFinalizeRequest) []byte {
	return hashFields([]byte("takusen:base-settlement"), []byte(message.RequestId), message.BaseSettlementTxHash)
}

func reassignmentSubject(message *MessageReassignRequest, attempt uint32) []byte {
	return hashFields(
		[]byte("takusen:reassignment"), []byte(message.RequestId), []byte(message.Model),
		uint32Bytes(attempt), uint64Bytes(message.NewDeadlineHeight),
	)
}

func (c *Contract) observe(kind byte, subject, observer []byte, height uint64) (*Observation, bool, *PluginError) {
	validators, totalStake, err := c.activeValidators()
	if err != nil {
		return nil, false, err
	}
	observerValidator, exists := validators[hex.EncodeToString(observer)]
	if !exists {
		return nil, false, ErrUnauthorized("observer is not an active validator in this committee")
	}
	entries, err := c.rangeRead(ObservationSubjectPrefix(kind, subject))
	if err != nil {
		return nil, false, err
	}
	observedStake := new(big.Int).SetUint64(observerValidator.StakedAmount)
	for _, entry := range entries {
		observation := new(Observation)
		if err = Unmarshal(entry.Value, observation); err != nil {
			return nil, false, err
		}
		if bytes.Equal(observation.ObserverAddress, observer) {
			return nil, false, ErrConflict("validator already submitted this observation")
		}
		if validator, found := validators[hex.EncodeToString(observation.ObserverAddress)]; found {
			observedStake.Add(observedStake, new(big.Int).SetUint64(validator.StakedAmount))
		}
	}
	left := new(big.Int).Mul(observedStake, big.NewInt(3))
	right := new(big.Int).Mul(new(big.Int).SetUint64(totalStake), big.NewInt(2))
	return &Observation{SubjectHash: subject, ObserverAddress: observer, ObservedHeight: height}, left.Cmp(right) > 0, nil
}

func (c *Contract) activeValidators() (map[string]*Validator, uint64, *PluginError) {
	entries, err := c.rangeRead(ValidatorPrefix())
	if err != nil {
		return nil, 0, err
	}
	validators := make(map[string]*Validator)
	var total uint64
	for _, entry := range entries {
		validator := new(Validator)
		if err = Unmarshal(entry.Value, validator); err != nil {
			return nil, 0, err
		}
		if validator.Delegate || validator.MaxPausedHeight != 0 || validator.UnstakingHeight != 0 || !containsCommittee(validator.Committees, c.Config.ChainId) {
			continue
		}
		if ^uint64(0)-total < validator.StakedAmount {
			return nil, 0, ErrState("validator stake overflow")
		}
		total += validator.StakedAmount
		validators[hex.EncodeToString(validator.Address)] = validator
	}
	if total == 0 {
		return nil, 0, ErrState("Takusen requires an active validator committee")
	}
	return validators, total, nil
}

func containsCommittee(committees []uint64, chainID uint64) bool {
	for _, committee := range committees {
		if committee == chainID {
			return true
		}
	}
	return false
}

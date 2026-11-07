package contract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const addressSize = 20

func validAddress(address []byte) bool { return len(address) == addressSize }
func validHash(hash []byte) bool       { return len(hash) == sha256.Size }

func validModels(models []string) bool {
	if len(models) == 0 || len(models) > 7 {
		return false
	}
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		if strings.TrimSpace(model) != model || model == "" || len(model) > 200 {
			return false
		}
		if _, exists := seen[model]; exists {
			return false
		}
		seen[model] = struct{}{}
	}
	return true
}

func validOutputType(outputType string) bool {
	switch outputType {
	case "boolean", "score", "choice", "private_hash":
		return true
	default:
		return false
	}
}

func checkObserveEnclave(message *MessageObserveEnclave) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validAddress(message.OwnerAddress) ||
		len(message.PublicKey) != ed25519.PublicKeySize || !validHash(message.AttestationHash) ||
		len(message.Pcr0) != 48 || len(message.Pcr1) != 48 || len(message.Pcr2) != 48 ||
		len(message.Nonce) == 0 || len(message.Nonce) > 64 || len(message.UserData) > 1024 ||
		len(message.ProofSignature) != ed25519.SignatureSize {
		return nil, ErrInvalidTransaction("invalid enclave observation")
	}
	keyDigest := sha256.Sum256(message.PublicKey)
	if message.TeeKeyId != "ed25519:"+hex.EncodeToString(keyDigest[:]) {
		return nil, ErrInvalidTransaction("TEE key identifier does not match its public key")
	}
	registrationDigest := sha256.New()
	_, _ = registrationDigest.Write([]byte("takusen:nitro-registration\x00"))
	_, _ = registrationDigest.Write(message.Nonce)
	_, _ = registrationDigest.Write([]byte{0})
	_, _ = registrationDigest.Write(message.UserData)
	if !ed25519.Verify(message.PublicKey, registrationDigest.Sum(nil), message.ProofSignature) {
		return nil, ErrCrypto("invalid enclave proof of possession")
	}
	return message.ObserverAddress, nil
}

func checkRevokeEnclave(message *MessageRevokeEnclave) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || message.TeeKeyId == "" || len(message.TeeKeyId) > 128 {
		return nil, ErrInvalidTransaction("invalid enclave revocation")
	}
	return message.ObserverAddress, nil
}

func checkRegisterServicer(message *MessageRegisterServicer) ([]byte, *PluginError) {
	if !validAddress(message.OwnerAddress) || !validAddress(message.PayoutAddress) || message.TeeKeyId == "" || message.Bond == 0 || !validModels(message.Models) {
		return nil, ErrInvalidTransaction("invalid servicer registration")
	}
	return message.OwnerAddress, nil
}

func checkUpdateServicer(message *MessageUpdateServicer) ([]byte, *PluginError) {
	if !validAddress(message.OwnerAddress) || !validAddress(message.PayoutAddress) || message.TeeKeyId == "" || !validModels(message.Models) {
		return nil, ErrInvalidTransaction("invalid servicer update")
	}
	return message.OwnerAddress, nil
}

func checkObserveAuthorization(message *MessageObserveAuthorization) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || message.RequestId == "" || len(message.RequestId) > 128 ||
		!validHash(message.InputHash) || !validAddress(message.Requester) || message.ReservedBudget == 0 ||
		!validOutputType(message.OutputType) || !validModels(message.Models) || message.ExecutionQuorum == 0 ||
		int(message.ExecutionQuorum) > len(message.Models) || !validHash(message.BaseTxHash) || message.DeadlineHeight == 0 {
		return nil, ErrInvalidTransaction("invalid Base authorization observation")
	}
	return message.ObserverAddress, nil
}

func checkSubmitExecution(message *MessageSubmitExecution) ([]byte, *PluginError) {
	if !validAddress(message.ServicerAddress) || len(message.ReceiptJson) == 0 || len(message.ReceiptJson) > 64*1024 ||
		len(message.PublicKey) != ed25519.PublicKeySize || len(message.Signature) != ed25519.SignatureSize ||
		message.ArchiveId == "" || len(message.ArchiveId) > 256 {
		return nil, ErrInvalidTransaction("invalid execution submission")
	}
	return message.ServicerAddress, nil
}

func checkReassignRequest(message *MessageReassignRequest) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || message.RequestId == "" || message.Model == "" || message.NewDeadlineHeight == 0 {
		return nil, ErrInvalidTransaction("invalid reassignment")
	}
	return message.ObserverAddress, nil
}

func checkFinalizeRequest(message *MessageFinalizeRequest) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || message.RequestId == "" || !validHash(message.BaseSettlementTxHash) {
		return nil, ErrInvalidTransaction("invalid settlement finalization")
	}
	return message.ObserverAddress, nil
}

func checkSubmitQuorumSignature(message *MessageSubmitQuorumSignature) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || message.ProofKind == "" || len(message.ProofKind) > 64 ||
		!validHash(message.ProofId) || !validHash(message.Digest) || !validHash(message.Message) ||
		message.ValidatorSetId == 0 || len(message.Signature) != 96 {
		return nil, ErrInvalidTransaction("invalid quorum signature share")
	}
	if !strings.EqualFold(hex.EncodeToString(message.Message), hex.EncodeToString(message.Digest)) {
		return nil, ErrInvalidTransaction("quorum message digest mismatch")
	}
	expectedID := quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
	if !strings.EqualFold(hex.EncodeToString(expectedID), hex.EncodeToString(message.ProofId)) {
		return nil, ErrInvalidTransaction("quorum proof identifier mismatch")
	}
	return message.ObserverAddress, nil
}

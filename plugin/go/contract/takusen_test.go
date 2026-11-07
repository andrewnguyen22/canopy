package contract

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
)

func TestAssignmentIsStableAndRotates(t *testing.T) {
	servicers := []*Servicer{{OwnerAddress: []byte{1}}, {OwnerAddress: []byte{2}}, {OwnerAddress: []byte{3}}}
	input := make([]byte, 32)
	anchor := make([]byte, 32)
	first := selectServicer(input, anchor, "model", 0, servicers)
	if first != selectServicer(input, anchor, "model", 0, servicers) {
		t.Fatal("assignment is not deterministic")
	}
	second := selectServicer(input, anchor, "model", 1, servicers)
	if string(first.OwnerAddress) == string(second.OwnerAddress) {
		t.Fatal("reassignment did not rotate to the next eligible servicer")
	}
}

func TestVerifyReceipt(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	outputDigest := sha256.Sum256([]byte("true"))
	commitment := "0x" + hex.EncodeToString(outputDigest[:])
	keyDigest := sha256.Sum256(publicKey)
	r := receipt{
		ExecutionID: "execution", RequestID: "request", InputHash: commitment, Model: "model",
		Status: "success", Output: "true", OutputHash: commitment, PromptTokens: 10, CompletionTokens: 1,
		CostMicros: 42, ProviderRequestHash: commitment, ProviderResponseHash: commitment,
		ExecutionNonce: commitment, TEEKeyID: "ed25519:" + hex.EncodeToString(keyDigest[:]),
		StartedAtMS: 1, CompletedAtMS: 2,
	}
	canonical, _ := json.Marshal([]any{
		r.ExecutionID, r.RequestID, r.InputHash, r.Model, r.Status, r.Output, r.OutputHash,
		strconv.FormatInt(r.PromptTokens, 10), strconv.FormatInt(r.CompletionTokens, 10), strconv.FormatInt(r.CostMicros, 10),
		r.ProviderRequestHash, r.ProviderResponseHash, r.ExecutionNonce, r.TEEKeyID,
		strconv.FormatInt(r.StartedAtMS, 10), strconv.FormatInt(r.CompletedAtMS, 10),
	})
	digest := sha256.Sum256(canonical)
	receiptJSON, _ := json.Marshal(r)
	message := &MessageSubmitExecution{
		ServicerAddress: make([]byte, 20), ReceiptJson: receiptJSON, PublicKey: publicKey,
		Signature: ed25519.Sign(privateKey, digest[:]), ArchiveId: "sha256:evidence",
	}
	parsed, verifiedDigest, verifyErr := verifyReceipt(message)
	if verifyErr != nil {
		t.Fatal(verifyErr)
	}
	if parsed.ExecutionID != r.ExecutionID || hex.EncodeToString(verifiedDigest) != hex.EncodeToString(digest[:]) {
		t.Fatal("verified receipt differs from signed receipt")
	}
	message.Signature[0] ^= 0xff
	if _, _, verifyErr = verifyReceipt(message); verifyErr == nil {
		t.Fatal("tampered receipt signature was accepted")
	}
}

func TestObservationSubjectsExcludeObserverOnly(t *testing.T) {
	message := &MessageObserveAuthorization{
		ObserverAddress: make([]byte, 20), RequestId: "request", InputHash: make([]byte, 32),
		Requester: make([]byte, 20), ReservedBudget: 100, OutputType: "boolean", Models: []string{"model"},
		ExecutionQuorum: 1, BaseTxHash: make([]byte, 32), DeadlineHeight: 100,
	}
	first := authorizationSubject(message)
	message.ObserverAddress[0] = 1
	second := authorizationSubject(message)
	if string(first) != string(second) {
		t.Fatal("observer identity changed the observed authorization subject")
	}
	message.ReservedBudget++
	if string(first) == string(authorizationSubject(message)) {
		t.Fatal("authorization content did not change its subject")
	}
}

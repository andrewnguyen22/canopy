package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
)

type receipt struct {
	ExecutionID          string `json:"executionId"`
	RequestID            string `json:"requestId"`
	InputHash            string `json:"inputHash"`
	Model                string `json:"model"`
	Status               string `json:"status"`
	Output               string `json:"output"`
	OutputHash           string `json:"outputHash"`
	PromptTokens         int64  `json:"promptTokens"`
	CompletionTokens     int64  `json:"completionTokens"`
	CostMicros           int64  `json:"costMicros"`
	ProviderRequestHash  string `json:"providerRequestHash"`
	ProviderResponseHash string `json:"providerResponseHash"`
	ExecutionNonce       string `json:"executionNonce"`
	TEEKeyID             string `json:"teeKeyId"`
	StartedAtMS          int64  `json:"startedAtMs"`
	CompletedAtMS        int64  `json:"completedAtMs"`
}

func (c *Contract) deliverSubmitExecution(height uint64, message *MessageSubmitExecution) *PluginDeliverResponse {
	parsed, digest, err := verifyReceipt(message)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if found, readErr := c.read(KeyForExecution(parsed.ExecutionID), new(ExecutionRecord)); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("execution identifier has already been committed")}
	}
	request := new(RequestRecord)
	if found, readErr := c.read(KeyForRequest(parsed.RequestID), request); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || request.Status == "settled" {
		return &PluginDeliverResponse{Error: ErrNotFound("active authorized request not found")}
	}
	inputHash, decodeErr := decodeHash(parsed.InputHash)
	if decodeErr != nil || !bytes.Equal(inputHash, request.InputHash) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("receipt input hash is not authorized")}
	}
	if parsed.Status == "success" {
		if outputErr := validateTypedOutput(request.OutputType, parsed.Output); outputErr != nil {
			return &PluginDeliverResponse{Error: outputErr}
		}
	}
	assignment := findAssignment(request, parsed.Model)
	if assignment == nil || assignment.Completed || !bytes.Equal(assignment.ServicerAddress, message.ServicerAddress) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("execution was not submitted by the assigned servicer")}
	}
	servicer := new(Servicer)
	if found, readErr := c.read(KeyForServicer(message.ServicerAddress), servicer); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || !servicer.Active || servicer.TeeKeyId != parsed.TEEKeyID {
		return &PluginDeliverResponse{Error: ErrUnauthorized("servicer or receipt TEE key is not active")}
	}
	enclave := new(EnclaveKey)
	if found, readErr := c.read(KeyForEnclave(parsed.TEEKeyID), enclave); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || !enclave.Active || !bytes.Equal(enclave.PublicKey, message.PublicKey) || !bytes.Equal(enclave.OwnerAddress, message.ServicerAddress) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("receipt key is not the registered enclave key")}
	}
	modelIndex := indexOf(request.Models, parsed.Model)
	modelBudget := request.ReservedBudget / uint64(len(request.Models))
	if uint64(modelIndex) < request.ReservedBudget%uint64(len(request.Models)) {
		modelBudget++
	}
	if uint64(parsed.CostMicros) > modelBudget || ^uint64(0)-request.Spent < uint64(parsed.CostMicros) || request.Spent+uint64(parsed.CostMicros) > request.ReservedBudget {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("execution exceeds its authorized budget")}
	}
	outputHash, _ := decodeHash(parsed.OutputHash)
	execution := &ExecutionRecord{
		ExecutionId: parsed.ExecutionID, RequestId: parsed.RequestID, Model: parsed.Model,
		ServicerAddress: append([]byte(nil), message.ServicerAddress...), Status: parsed.Status, Output: parsed.Output,
		OutputHash: outputHash, Cost: uint64(parsed.CostMicros), TeeKeyId: parsed.TEEKeyID,
		ReceiptDigest: digest, ArchiveId: message.ArchiveId, CommittedHeight: height,
	}
	assignment.Completed = true
	assignment.ExecutionId = parsed.ExecutionID
	request.Spent += uint64(parsed.CostMicros)
	records := map[string]proto.Message{
		string(KeyForExecution(parsed.ExecutionID)): execution,
		string(KeyForRequest(request.RequestId)):    request,
	}
	completed := completedExecutions(request)
	if uint32(completed) >= request.ExecutionQuorum {
		request.Status = "quorum_reached"
		executions, collectErr := c.collectExecutions(request, execution)
		if collectErr != nil {
			return &PluginDeliverResponse{Error: collectErr}
		}
		consensusHash, agreement := agreement(executions)
		request.ConsensusOutputHash = consensusHash
		request.AgreementCount = agreement
		settlement := &SettlementRecord{
			RequestId: request.RequestId, Executions: executions, TotalCost: request.Spent,
			CompletedHeight: height, Status: "pending",
		}
		settlement.SettlementDigest = settlementDigest(settlement)
		records[string(KeyForSettlement(request.RequestId))] = settlement
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func verifyReceipt(message *MessageSubmitExecution) (*receipt, []byte, *PluginError) {
	parsed := new(receipt)
	if err := json.Unmarshal(message.ReceiptJson, parsed); err != nil {
		return nil, nil, ErrInvalidTransaction("receipt JSON is invalid")
	}
	if parsed.ExecutionID == "" || len(parsed.ExecutionID) > 128 || parsed.RequestID == "" || parsed.Model == "" ||
		parsed.CostMicros < 0 || parsed.PromptTokens < 0 || parsed.CompletionTokens < 0 || parsed.StartedAtMS <= 0 || parsed.CompletedAtMS < parsed.StartedAtMS {
		return nil, nil, ErrInvalidTransaction("receipt fields are invalid")
	}
	if _, err := decodeHash(parsed.InputHash); err != nil {
		return nil, nil, ErrInvalidTransaction("receipt input hash is invalid")
	}
	for _, hash := range []string{parsed.OutputHash, parsed.ProviderRequestHash, parsed.ProviderResponseHash, parsed.ExecutionNonce} {
		if _, err := decodeHash(hash); err != nil {
			return nil, nil, ErrInvalidTransaction("receipt commitment is invalid")
		}
	}
	outputDigest := sha256.Sum256([]byte(parsed.Output))
	if parsed.OutputHash != "0x"+hex.EncodeToString(outputDigest[:]) {
		return nil, nil, ErrInvalidTransaction("receipt output hash mismatch")
	}
	switch parsed.Status {
	case "success":
	case "budget_exhausted", "provider_failure":
		if parsed.Output != "" {
			return nil, nil, ErrInvalidTransaction("non-answer receipt contains an output")
		}
		if parsed.Status == "provider_failure" && parsed.CostMicros != 0 {
			return nil, nil, ErrInvalidTransaction("provider failure cannot charge execution cost")
		}
	default:
		return nil, nil, ErrInvalidTransaction("receipt status is invalid")
	}
	keyDigest := sha256.Sum256(message.PublicKey)
	if parsed.TEEKeyID != "ed25519:"+hex.EncodeToString(keyDigest[:]) {
		return nil, nil, ErrInvalidTransaction("receipt TEE key identifier mismatch")
	}
	canonical, _ := json.Marshal([]any{
		parsed.ExecutionID, parsed.RequestID, parsed.InputHash, parsed.Model, parsed.Status, parsed.Output, parsed.OutputHash,
		strconv.FormatInt(parsed.PromptTokens, 10), strconv.FormatInt(parsed.CompletionTokens, 10), strconv.FormatInt(parsed.CostMicros, 10),
		parsed.ProviderRequestHash, parsed.ProviderResponseHash, parsed.ExecutionNonce, parsed.TEEKeyID,
		strconv.FormatInt(parsed.StartedAtMS, 10), strconv.FormatInt(parsed.CompletedAtMS, 10),
	})
	digest := sha256.Sum256(canonical)
	if !ed25519.Verify(message.PublicKey, digest[:], message.Signature) {
		return nil, nil, ErrCrypto("receipt signature mismatch")
	}
	return parsed, digest[:], nil
}

func validateTypedOutput(kind, value string) *PluginError {
	switch kind {
	case "boolean":
		if value == "true" || value == "false" {
			return nil
		}
	case "choice":
		if len(value) == 1 && value[0] >= 'A' && value[0] <= 'Z' {
			return nil
		}
	case "score":
		if score, err := strconv.Atoi(value); err == nil && score >= 0 && score <= 100 && strconv.Itoa(score) == value {
			return nil
		}
	case "private_hash":
		if decoded, err := decodeHash(value); err == nil && len(decoded) == sha256.Size {
			return nil
		}
	}
	return ErrInvalidTransaction("receipt output does not match the authorized type")
}

func decodeHash(value string) ([]byte, error) {
	if len(value) != 66 || !strings.HasPrefix(value, "0x") {
		return nil, hex.ErrLength
	}
	return hex.DecodeString(value[2:])
}

func indexOf(values []string, wanted string) int {
	for index, value := range values {
		if value == wanted {
			return index
		}
	}
	return -1
}

func completedExecutions(request *RequestRecord) int {
	count := 0
	for _, assignment := range request.Assignments {
		if assignment.Completed {
			count++
		}
	}
	return count
}

func (c *Contract) collectExecutions(request *RequestRecord, current *ExecutionRecord) ([]*ExecutionRecord, *PluginError) {
	executions := make([]*ExecutionRecord, 0, completedExecutions(request))
	for _, assignment := range request.Assignments {
		if !assignment.Completed {
			continue
		}
		if assignment.ExecutionId == current.ExecutionId {
			executions = append(executions, current)
			continue
		}
		execution := new(ExecutionRecord)
		if found, err := c.read(KeyForExecution(assignment.ExecutionId), execution); err != nil {
			return nil, err
		} else if !found {
			return nil, ErrState("completed assignment has no execution record")
		}
		executions = append(executions, execution)
	}
	return executions, nil
}

func agreement(executions []*ExecutionRecord) ([]byte, uint32) {
	counts := make(map[string]uint32)
	var best []byte
	var bestCount uint32
	for _, execution := range executions {
		if execution.Status != "success" {
			continue
		}
		key := string(execution.OutputHash)
		counts[key]++
		if counts[key] > bestCount || counts[key] == bestCount && bytes.Compare(execution.OutputHash, best) < 0 {
			best = append([]byte(nil), execution.OutputHash...)
			bestCount = counts[key]
		}
	}
	return best, bestCount
}

func settlementDigest(settlement *SettlementRecord) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("takusen:settlement\x00"))
	_, _ = h.Write([]byte(settlement.RequestId))
	for _, execution := range settlement.Executions {
		_, _ = h.Write(execution.ReceiptDigest)
	}
	_, _ = h.Write(uint64Bytes(settlement.TotalCost))
	return h.Sum(nil)
}

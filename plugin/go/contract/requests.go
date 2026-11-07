package contract

import (
	"bytes"
	"encoding/binary"
	"sort"

	"google.golang.org/protobuf/proto"
)

func (c *Contract) deliverObserveAuthorization(height uint64, message *MessageObserveAuthorization) *PluginDeliverResponse {
	if found, err := c.read(KeyForRequest(message.RequestId), new(RequestRecord)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("request is already authorized")}
	}
	subject := authorizationSubject(message)
	observation, reached, err := c.observe(observationAuthorization, subject, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := map[string]proto.Message{
		string(KeyForObservation(observationAuthorization, subject, message.ObserverAddress)): observation,
	}
	if reached {
		if message.DeadlineHeight <= height {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("request deadline has already elapsed")}
		}
		anchor := new(BlockAnchor)
		if found, readErr := c.read(KeyForBlockAnchor(), anchor); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || anchor.Height != height || len(anchor.PreviousBlockHash) == 0 {
			return &PluginDeliverResponse{Error: ErrState("current finalized-block assignment anchor is unavailable")}
		}
		assignments := make([]*Assignment, 0, len(message.Models))
		for _, model := range message.Models {
			servicers, selectErr := c.eligibleServicers(model)
			if selectErr != nil {
				return &PluginDeliverResponse{Error: selectErr}
			}
			if len(servicers) == 0 {
				return &PluginDeliverResponse{Error: ErrState("no bonded servicer supports model " + model)}
			}
			selected := selectServicer(message.InputHash, anchor.PreviousBlockHash, model, 0, servicers)
			assignments = append(assignments, &Assignment{Model: model, ServicerAddress: selected.OwnerAddress})
		}
		records[string(KeyForRequest(message.RequestId))] = &RequestRecord{
			RequestId: message.RequestId, InputHash: message.InputHash, Requester: message.Requester,
			ReservedBudget: message.ReservedBudget, OutputType: message.OutputType, Models: append([]string(nil), message.Models...),
			ExecutionQuorum: message.ExecutionQuorum, BaseTxHash: message.BaseTxHash, DeadlineHeight: message.DeadlineHeight,
			AuthorizedHeight: height, AssignmentSeed: anchor.PreviousBlockHash, Assignments: assignments, Status: "authorized",
		}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) deliverReassignRequest(height uint64, message *MessageReassignRequest) *PluginDeliverResponse {
	request := new(RequestRecord)
	if found, err := c.read(KeyForRequest(message.RequestId), request); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || request.Status == "settled" {
		return &PluginDeliverResponse{Error: ErrNotFound("active request not found")}
	}
	if height <= request.DeadlineHeight || message.NewDeadlineHeight <= height {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("reassignment requires an elapsed deadline and a future replacement deadline")}
	}
	assignment := findAssignment(request, message.Model)
	if assignment == nil || assignment.Completed {
		return &PluginDeliverResponse{Error: ErrConflict("model assignment is absent or already completed")}
	}
	nextAttempt := assignment.Attempt + 1
	subject := reassignmentSubject(message, nextAttempt)
	observation, reached, err := c.observe(observationReassignment, subject, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := map[string]proto.Message{
		string(KeyForObservation(observationReassignment, subject, message.ObserverAddress)): observation,
	}
	if reached {
		servicers, selectErr := c.eligibleServicers(message.Model)
		if selectErr != nil {
			return &PluginDeliverResponse{Error: selectErr}
		}
		if len(servicers) == 0 {
			return &PluginDeliverResponse{Error: ErrState("no bonded servicer supports model " + message.Model)}
		}
		previousAddress := append([]byte(nil), assignment.ServicerAddress...)
		selected := selectServicer(request.InputHash, request.AssignmentSeed, message.Model, nextAttempt, servicers)
		assignment.ServicerAddress = append([]byte(nil), selected.OwnerAddress...)
		assignment.Attempt = nextAttempt
		request.DeadlineHeight = message.NewDeadlineHeight
		records[string(KeyForRequest(request.RequestId))] = request
		previous := new(Servicer)
		if found, readErr := c.read(KeyForServicer(previousAddress), previous); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found {
			previous.FailureCount++
			records[string(KeyForServicer(previousAddress))] = previous
		}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) deliverFinalizeRequest(height uint64, message *MessageFinalizeRequest) *PluginDeliverResponse {
	request := new(RequestRecord)
	if found, err := c.read(KeyForRequest(message.RequestId), request); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || request.Status != "quorum_reached" {
		return &PluginDeliverResponse{Error: ErrConflict("request is not ready for settlement finalization")}
	}
	settlement := new(SettlementRecord)
	if found, err := c.read(KeyForSettlement(message.RequestId), settlement); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || settlement.Status != "pending" {
		return &PluginDeliverResponse{Error: ErrConflict("settlement is not pending")}
	}
	subject := settlementSubject(message)
	observation, reached, err := c.observe(observationSettlement, subject, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := map[string]proto.Message{
		string(KeyForObservation(observationSettlement, subject, message.ObserverAddress)): observation,
	}
	if reached {
		request.Status = "settled"
		request.BaseSettlementTxHash = append([]byte(nil), message.BaseSettlementTxHash...)
		settlement.Status = "settled"
		settlement.BaseTxHash = append([]byte(nil), message.BaseSettlementTxHash...)
		records[string(KeyForRequest(message.RequestId))] = request
		records[string(KeyForSettlement(message.RequestId))] = settlement
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) eligibleServicers(model string) ([]*Servicer, *PluginError) {
	entries, err := c.rangeRead(ServicerPrefix())
	if err != nil {
		return nil, err
	}
	servicers := make([]*Servicer, 0, len(entries))
	for _, entry := range entries {
		servicer := new(Servicer)
		if err = Unmarshal(entry.Value, servicer); err != nil {
			return nil, err
		}
		if !servicer.Active || servicer.Bond == 0 || !containsString(servicer.Models, model) {
			continue
		}
		enclave := new(EnclaveKey)
		if found, readErr := c.read(KeyForEnclave(servicer.TeeKeyId), enclave); readErr != nil {
			return nil, readErr
		} else if !found || !enclave.Active || !bytes.Equal(enclave.OwnerAddress, servicer.OwnerAddress) {
			continue
		}
		servicers = append(servicers, servicer)
	}
	sort.Slice(servicers, func(i, j int) bool { return bytes.Compare(servicers[i].OwnerAddress, servicers[j].OwnerAddress) < 0 })
	return servicers, nil
}

func selectServicer(inputHash, previousBlockHash []byte, model string, attempt uint32, servicers []*Servicer) *Servicer {
	digest := hashFields([]byte("takusen:assignment"), inputHash, previousBlockHash, []byte(model))
	base := binary.BigEndian.Uint64(digest[:8])
	return servicers[(base+uint64(attempt))%uint64(len(servicers))]
}

func findAssignment(request *RequestRecord, model string) *Assignment {
	for _, assignment := range request.Assignments {
		if assignment.Model == model {
			return assignment
		}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

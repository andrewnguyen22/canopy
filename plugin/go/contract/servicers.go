package contract

import "google.golang.org/protobuf/proto"

func (c *Contract) deliverObserveEnclave(height uint64, message *MessageObserveEnclave) *PluginDeliverResponse {
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), new(EnclaveKey)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("enclave key is already registered")}
	}
	subject := enclaveSubject(message)
	observation, reached, err := c.observe(observationEnclave, subject, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := map[string]proto.Message{
		string(KeyForObservation(observationEnclave, subject, message.ObserverAddress)): observation,
	}
	if reached {
		records[string(KeyForEnclave(message.TeeKeyId))] = &EnclaveKey{
			OwnerAddress: message.OwnerAddress, TeeKeyId: message.TeeKeyId, PublicKey: message.PublicKey,
			AttestationHash: message.AttestationHash, Pcr0: message.Pcr0, Pcr1: message.Pcr1, Pcr2: message.Pcr2,
			RegisteredHeight: height, Active: true,
		}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) deliverRevokeEnclave(height uint64, message *MessageRevokeEnclave) *PluginDeliverResponse {
	enclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), enclave); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || !enclave.Active {
		return &PluginDeliverResponse{Error: ErrNotFound("active enclave key not found")}
	}
	subject := revocationSubject(message)
	observation, reached, err := c.observe(observationRevocation, subject, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := map[string]proto.Message{
		string(KeyForObservation(observationRevocation, subject, message.ObserverAddress)): observation,
	}
	if reached {
		enclave.Active = false
		records[string(KeyForEnclave(message.TeeKeyId))] = enclave
		entries, rangeErr := c.rangeRead(ServicerPrefix())
		if rangeErr != nil {
			return &PluginDeliverResponse{Error: rangeErr}
		}
		for _, entry := range entries {
			servicer := new(Servicer)
			if decodeErr := Unmarshal(entry.Value, servicer); decodeErr != nil {
				return &PluginDeliverResponse{Error: decodeErr}
			}
			if servicer.TeeKeyId == message.TeeKeyId && servicer.Active {
				servicer.Active = false
				records[string(entry.Key)] = servicer
			}
		}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) deliverRegisterServicer(height uint64, message *MessageRegisterServicer) *PluginDeliverResponse {
	if found, err := c.read(KeyForServicer(message.OwnerAddress), new(Servicer)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("servicer is already registered")}
	}
	enclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), enclave); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || !enclave.Active || string(enclave.OwnerAddress) != string(message.OwnerAddress) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("servicer does not own an active enclave key")}
	}
	account := new(Account)
	if found, err := c.read(KeyForAccount(message.OwnerAddress), account); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || account.Amount < message.Bond {
		return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
	}
	account.Amount -= message.Bond
	servicer := &Servicer{
		OwnerAddress: message.OwnerAddress, PayoutAddress: message.PayoutAddress, TeeKeyId: message.TeeKeyId,
		Models: append([]string(nil), message.Models...), Bond: message.Bond, Active: true, RegisteredHeight: height,
	}
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{
		string(KeyForAccount(message.OwnerAddress)):  account,
		string(KeyForServicer(message.OwnerAddress)): servicer,
	})}
}

func (c *Contract) deliverUpdateServicer(message *MessageUpdateServicer) *PluginDeliverResponse {
	servicer := new(Servicer)
	if found, err := c.read(KeyForServicer(message.OwnerAddress), servicer); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found {
		return &PluginDeliverResponse{Error: ErrNotFound("servicer is not registered")}
	}
	enclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), enclave); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || !enclave.Active || string(enclave.OwnerAddress) != string(message.OwnerAddress) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("servicer does not own an active enclave key")}
	}
	records := map[string]proto.Message{}
	if message.AdditionalBond != 0 {
		account := new(Account)
		if found, err := c.read(KeyForAccount(message.OwnerAddress), account); err != nil {
			return &PluginDeliverResponse{Error: err}
		} else if !found || account.Amount < message.AdditionalBond || ^uint64(0)-servicer.Bond < message.AdditionalBond {
			return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
		}
		account.Amount -= message.AdditionalBond
		servicer.Bond += message.AdditionalBond
		records[string(KeyForAccount(message.OwnerAddress))] = account
	}
	servicer.PayoutAddress = message.PayoutAddress
	servicer.TeeKeyId = message.TeeKeyId
	servicer.Models = append([]string(nil), message.Models...)
	servicer.Active = message.Active
	records[string(KeyForServicer(message.OwnerAddress))] = servicer
	return &PluginDeliverResponse{Error: c.write(records)}
}

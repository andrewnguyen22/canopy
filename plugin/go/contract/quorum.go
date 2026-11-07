package contract

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"sort"

	"github.com/drand/kyber"
	drandbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/bdn"
	kilicbls "github.com/kilic/bls12-381"
	"google.golang.org/protobuf/proto"
)

const bdnSignatureSize = 96

var allowedProofKinds = map[string]bool{
	"settlement":             true,
	"finalization":           true,
	"bridge-release":         true,
	"epoch-rewards":          true,
	"validator-set-rotation": true,
}

func quorumProofID(kind string, setID uint64, digest []byte) []byte {
	return hashFields([]byte("takusen:base-quorum-proof"), []byte(kind), uint64Bytes(setID), digest)
}

func validatorSetHash(validators []*Validator) []byte {
	fields := make([][]byte, 0, 1+len(validators)*3)
	fields = append(fields, []byte("takusen:validator-set"))
	for _, validator := range validators {
		fields = append(fields, validator.Address, validator.PublicKey, uint64Bytes(validator.StakedAmount))
	}
	return hashFields(fields...)
}

func (c *Contract) deliverSubmitQuorumSignature(height uint64, message *MessageSubmitQuorumSignature) *PluginDeliverResponse {
	if !allowedProofKinds[message.ProofKind] {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("unsupported quorum proof kind")}
	}
	completed := new(QuorumProof)
	if found, err := c.read(KeyForQuorumProof(message.ProofId), completed); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("quorum proof already finalized")}
	}

	validatorsByAddress, totalWeight, err := c.activeValidators()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	observer, ok := validatorsByAddress[hex.EncodeToString(message.ObserverAddress)]
	if !ok {
		return &PluginDeliverResponse{Error: ErrUnauthorized("quorum signer is not an active validator")}
	}
	publicKey, cryptoErr := bdnPublicKey(observer.PublicKey)
	if cryptoErr != nil || bdnScheme().Verify(publicKey, message.Message, message.Signature) != nil {
		return &PluginDeliverResponse{Error: ErrCrypto("invalid validator BDN signature share")}
	}

	shareKey := KeyForQuorumShare(message.ProofId, message.ObserverAddress)
	prior := new(QuorumSignatureShare)
	if found, readErr := c.read(shareKey, prior); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("validator already submitted this quorum signature")}
	}
	share := &QuorumSignatureShare{
		ProofId: message.ProofId, ObserverAddress: message.ObserverAddress,
		Signature: message.Signature, ObservedHeight: height,
	}
	records := map[string]proto.Message{string(shareKey): share}

	validators := make([]*Validator, 0, len(validatorsByAddress))
	for _, validator := range validatorsByAddress {
		validators = append(validators, validator)
	}
	sort.Slice(validators, func(i, j int) bool {
		return bytes.Compare(validators[i].PublicKey, validators[j].PublicKey) < 0
	})
	shares, readErr := c.rangeRead(QuorumShareProofPrefix(message.ProofId))
	if readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	}
	signatures := map[string][]byte{hex.EncodeToString(message.ObserverAddress): message.Signature}
	for _, entry := range shares {
		stored := new(QuorumSignatureShare)
		if decodeErr := Unmarshal(entry.Value, stored); decodeErr != nil {
			return &PluginDeliverResponse{Error: decodeErr}
		}
		signatures[hex.EncodeToString(stored.ObserverAddress)] = stored.Signature
	}

	var signedWeight uint64
	for _, validator := range validators {
		if _, signed := signatures[hex.EncodeToString(validator.Address)]; signed {
			if ^uint64(0)-signedWeight < validator.StakedAmount {
				return &PluginDeliverResponse{Error: ErrState("signed validator stake overflow")}
			}
			signedWeight += validator.StakedAmount
		}
	}
	left := new(big.Int).Mul(new(big.Int).SetUint64(signedWeight), big.NewInt(3))
	right := new(big.Int).Mul(new(big.Int).SetUint64(totalWeight), big.NewInt(2))
	if left.Cmp(right) > 0 {
		proof, proofErr := buildQuorumProof(height, message, validators, signatures, signedWeight, totalWeight)
		if proofErr != nil {
			return &PluginDeliverResponse{Error: ErrCrypto(proofErr.Error())}
		}
		records[string(KeyForQuorumProof(message.ProofId))] = proof
	}
	if writeErr := c.write(records); writeErr != nil {
		return &PluginDeliverResponse{Error: writeErr}
	}
	return &PluginDeliverResponse{}
}

func buildQuorumProof(height uint64, message *MessageSubmitQuorumSignature, validators []*Validator, signatures map[string][]byte, signedWeight, totalWeight uint64) (*QuorumProof, error) {
	suite := drandbls.NewBLS12381Suite()
	points := make([]kyber.Point, len(validators))
	for i, validator := range validators {
		point, err := bdnPublicKey(validator.PublicKey)
		if err != nil {
			return nil, err
		}
		points[i] = point
	}
	mask, err := sign.NewMask(suite, points, nil)
	if err != nil {
		return nil, err
	}
	partialSignatures := make([][]byte, 0, len(signatures))
	for i, validator := range validators {
		if signature, ok := signatures[hex.EncodeToString(validator.Address)]; ok {
			if err = mask.SetBit(i, true); err != nil {
				return nil, err
			}
			partialSignatures = append(partialSignatures, signature)
		}
	}
	scheme := bdn.NewSchemeOnG2(suite)
	aggregate, err := scheme.AggregateSignatures(partialSignatures, mask)
	if err != nil {
		return nil, err
	}
	aggregatePublicKey, err := scheme.AggregatePublicKeys(mask)
	if err != nil {
		return nil, err
	}
	aggregateSignature, err := aggregate.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err = scheme.Verify(aggregatePublicKey, message.Message, aggregateSignature); err != nil {
		return nil, err
	}
	eipSignature, err := g2CompressedToEIP2537(aggregateSignature)
	if err != nil {
		return nil, err
	}
	members := make([]*QuorumProofMember, len(validators))
	for i, validator := range validators {
		single, maskErr := sign.NewMask(suite, points, nil)
		if maskErr != nil {
			return nil, maskErr
		}
		if maskErr = single.SetBit(i, true); maskErr != nil {
			return nil, maskErr
		}
		weighted, maskErr := scheme.AggregatePublicKeys(single)
		if maskErr != nil {
			return nil, maskErr
		}
		compressed, maskErr := weighted.MarshalBinary()
		if maskErr != nil {
			return nil, maskErr
		}
		uncompressed, maskErr := g1CompressedToEIP2537(compressed)
		if maskErr != nil {
			return nil, maskErr
		}
		members[i] = &QuorumProofMember{
			Address: validator.Address, PublicKey: validator.PublicKey,
			WeightedPublicKeyEip2537: uncompressed, Weight: validator.StakedAmount,
		}
	}
	return &QuorumProof{
		ProofKind: message.ProofKind, ProofId: message.ProofId, Digest: message.Digest,
		Message: message.Message, ValidatorSetId: message.ValidatorSetId,
		ValidatorSetHash: validatorSetHash(validators), Members: members,
		SignerBitmap: mask.Mask(), AggregateSignature: aggregateSignature,
		AggregateSignatureEip2537: eipSignature, SignedWeight: signedWeight,
		TotalWeight: totalWeight, CompletedHeight: height,
	}, nil
}

func bdnScheme() *bdn.Scheme { return bdn.NewSchemeOnG2(drandbls.NewBLS12381Suite()) }

func bdnPublicKey(compressed []byte) (kyber.Point, error) {
	point := drandbls.NewBLS12381Suite().G1().Point()
	if err := point.UnmarshalBinary(compressed); err != nil {
		return nil, err
	}
	return point, nil
}

func g1CompressedToEIP2537(compressed []byte) ([]byte, error) {
	g1 := kilicbls.NewG1()
	point, err := g1.FromCompressed(compressed)
	if err != nil {
		return nil, err
	}
	raw := g1.ToUncompressed(point)
	result := make([]byte, 128)
	copy(result[16:64], raw[:48])
	copy(result[80:128], raw[48:])
	return result, nil
}

func g2CompressedToEIP2537(compressed []byte) ([]byte, error) {
	g2 := kilicbls.NewG2()
	point, err := g2.FromCompressed(compressed)
	if err != nil {
		return nil, err
	}
	// kilic serializes Fp2 as c1 || c0; EIP-2537 requires c0 || c1,
	// and pads each 48-byte field element to 64 bytes.
	raw := g2.ToUncompressed(point)
	result := make([]byte, 256)
	for coordinate := 0; coordinate < 2; coordinate++ {
		source := coordinate * 96
		target := coordinate * 128
		copy(result[target+16:target+64], raw[source+48:source+96])
		copy(result[target+80:target+128], raw[source:source+48])
	}
	return result, nil
}

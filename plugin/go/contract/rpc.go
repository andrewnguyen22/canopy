package contract

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
)

func (p *Plugin) StartRPCServer() {
	addr := p.config.RPCAddress
	if addr == "" {
		log.Println("Takusen plugin RPC server disabled")
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "module": "takusen", "build": PluginBuild})
	})
	mux.HandleFunc("GET /v1/takusen/requests/{id}", p.recordHandler(func(id string) []byte { return KeyForRequest(id) }, func() proto.Message { return new(RequestRecord) }))
	mux.HandleFunc("GET /v1/takusen/executions/{id}", p.recordHandler(func(id string) []byte { return KeyForExecution(id) }, func() proto.Message { return new(ExecutionRecord) }))
	mux.HandleFunc("GET /v1/takusen/enclaves/{id}", p.recordHandler(func(id string) []byte { return KeyForEnclave(id) }, func() proto.Message { return new(EnclaveKey) }))
	mux.HandleFunc("GET /v1/takusen/servicers", p.listHandler(ServicerPrefix(), func() proto.Message { return new(Servicer) }))
	mux.HandleFunc("GET /v1/takusen/requests", p.listHandler(RequestPrefix(), func() proto.Message { return new(RequestRecord) }))
	mux.HandleFunc("GET /v1/takusen/settlements", p.listHandler(SettlementPrefix(), func() proto.Message { return new(SettlementRecord) }))
	mux.HandleFunc("GET /v1/takusen/quorum-proofs/{id}", p.quorumProofHandler())
	mux.HandleFunc("GET /v1/takusen/quorum-proofs", p.listHandler(QuorumProofPrefix(), func() proto.Message { return new(QuorumProof) }))
	log.Printf("Takusen plugin RPC server (%s) listening on %s", PluginBuild, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("Takusen plugin RPC server error: %v", err)
	}
}

func (p *Plugin) quorumProofHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proofID, err := hex.DecodeString(strings.TrimPrefix(r.PathValue("id"), "0x"))
		if err != nil || len(proofID) != 32 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "proof id must be 32-byte hexadecimal"})
			return
		}
		p.recordHandler(func(string) []byte { return KeyForQuorumProof(proofID) }, func() proto.Message { return new(QuorumProof) })(w, r)
	}
}

func (p *Plugin) recordHandler(key func(string) []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		response, err := p.QueryState(height, &PluginStateReadRequest{Keys: []*PluginKeyRead{{QueryId: 1, Key: key(r.PathValue("id"))}}})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		if len(response.Results) != 1 || len(response.Results[0].Entries) == 0 || len(response.Results[0].Entries[0].Value) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "record not found"})
			return
		}
		record := value()
		if decodeErr := Unmarshal(response.Results[0].Entries[0].Value, record); decodeErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, record)
	}
}

func (p *Plugin) listHandler(prefix []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		response, err := p.QueryState(height, &PluginStateReadRequest{Ranges: []*PluginRangeRead{{QueryId: 1, Prefix: prefix, Limit: 5000}}})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		result := make([]any, 0)
		if len(response.Results) == 1 {
			for _, entry := range response.Results[0].Entries {
				record := value()
				if decodeErr := Unmarshal(entry.Value, record); decodeErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
					return
				}
				if status := r.URL.Query().Get("status"); status != "" && !recordHasStatus(record, status) {
					continue
				}
				result = append(result, record)
			}
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func recordHasStatus(record proto.Message, wanted string) bool {
	switch record := record.(type) {
	case *RequestRecord:
		return record.Status == wanted
	case *SettlementRecord:
		return record.Status == wanted
	default:
		return true
	}
}

func queryHeight(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	value := strings.TrimSpace(r.URL.Query().Get("height"))
	if value == "" {
		return 0, true
	}
	height, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "height must be an unsigned integer"})
		return 0, false
	}
	return height, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

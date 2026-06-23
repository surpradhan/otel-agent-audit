// Package canonical provides deterministic serialization of AuditRecord values.
//
// Marshal produces byte-identical output for equal records across runs and
// language implementations. The output format is a compact JSON object whose
// field order follows the AuditRecord struct declaration — that order is
// load-bearing and is locked by the golden fixture in testdata/.
//
package canonical

import (
	"encoding/json"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
)

// Marshal serialises r to compact canonical JSON.
// Field order follows record.AuditRecord's struct declaration; do not change
// either without a schema_version bump and fixture update.
func Marshal(r record.AuditRecord) ([]byte, error) {
	return json.Marshal(r)
}

// Unmarshal deserialises canonical JSON bytes into an AuditRecord.
func Unmarshal(b []byte) (record.AuditRecord, error) {
	var r record.AuditRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return record.AuditRecord{}, err
	}
	return r, nil
}

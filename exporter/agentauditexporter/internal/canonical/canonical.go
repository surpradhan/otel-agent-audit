// Package canonical provides deterministic serialization of AuditRecord values.
//
// Marshal produces byte-identical output for equal records across runs and
// language implementations. The output format is a compact JSON object whose
// field order follows the AuditRecord struct declaration — that order is
// load-bearing and is locked by the golden fixture in testdata/.
//
// Since v3, start_time_unix_nano and end_time_unix_nano are encoded as decimal
// strings rather than JSON numbers, so an implementation that parses JSON
// numbers as IEEE-754 doubles can still reproduce these bytes exactly (see
// record.UnixNano). v1/v2 records keep their numeric encoding; the dispatch is
// on the record's own schema_version, inside record.AuditRecord.MarshalJSON.
//
package canonical

import (
	"encoding/json"

	"github.com/surpradhan/otel-agent-audit/exporter/agentauditexporter/internal/record"
)

// Marshal serialises r to compact canonical JSON.
// Field order follows record.AuditRecord's struct declaration and the
// timestamp encoding follows r.SchemaVersion; do not change either without a
// schema_version bump and fixture update.
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

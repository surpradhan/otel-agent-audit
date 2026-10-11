# Comparison with `otel-span/canonical/1`

[`otel-span/canonical/1`](https://github.com/MarkovianProtocol/otel-canonical-profile)
is a published canonical form and hash for an OpenTelemetry span, with pass and
reject conformance vectors. This page records what happened when this repo's
serialization was run next to an implementation of that profile: what agrees,
what differs on purpose, and where either side is the weaker one.

- Profile version compared: commit `4f8c4c5a55d3bf79fd402c6c6e49bff9e6afe45d` (2026-08-05), a draft.
  Its [SPEC.md](https://github.com/MarkovianProtocol/otel-canonical-profile/blob/4f8c4c5a55d3bf79fd402c6c6e49bff9e6afe45d/SPEC.md) is the text quoted below.
- Code: `exporter/agentauditexporter/internal/profilecompare/`
  (test-only; nothing in `internal/record` or `internal/canonical` is touched).
- Vectors: copied verbatim to `testdata/otel-canonical-profile/`, with their
  Apache-2.0 licence and a provenance file listing the commit and per-file hashes.
- Reproduce: `cd exporter/agentauditexporter && go test ./internal/profilecompare -v`

Every claim below is tagged **run** (a test in that package exercises it) or
**read** (taken from reading the profile's reference code, `canonical.py` and
`validate.mjs`, which were deliberately not executed: this repo does not run
third-party code).

## Result

| Check | Outcome |
|---|---|
| 8 pass vectors: published `span_sha256` and `attributes_sha256` | reproduced |
| 8 pass vectors rebuilt from raw span fields and attribute values | identical bytes |
| 9 reject vectors | all refused with the named code |
| Batch root over the 3-member batch | reproduced |

The implementation (`profile_test.go`) is Go written from SPEC.md, following
`canonical.py` where SPEC.md is silent (the choices are listed in the header of
that file), using RFC 8785 from `github.com/gowebpki/jcs`. It was
mutation-checked: rules were broken one at a time, in the implementation and in
this repo's own record and chain code, and a test had to fail. A crash such as a
stack overflow counts as failing; a mutant that did not compile did not count.
Several rules survived the vendored vectors alone and are covered by this repo's
own tests instead (see "Coverage the vectors lack").

## The two forms hash different objects

They are not expected to produce the same bytes, and do not
(`TestCompare_HashesNeverCoincide`).

| | Profile | This repo (`AuditRecord`) |
|---|---|---|
| Serialization | RFC 8785 (JCS) | `encoding/json` in struct-declaration order, locked by a golden fixture |
| Unit hashed | one span, standalone | one span record, chained per trace and signed |
| Commitment above that | RFC 6962 Merkle root over a batch | signed checkpoint over trace tips |
| Span identity | `trace_id`, `span_id`, `parent_span_id`, `name` | same four (`span_name`) |
| Times | decimal strings | decimal strings from schema v3 |
| Kind, status | OTLP numbers | names (`Server`, `Ok`) |
| Attributes | every attribute, folded in as `attributes_sha256` | an allowlist of ten `gen_ai.*` keys, stringified |
| Fields only here | | `schema_version`, `seq_in_trace`, `gen_ai_operation`, `audit_kind` |

## Where they agree (run)

`TestCompare_SharedFieldsAgree`, on all 8 vectors: the four identity fields and
both timestamps are equal, including `uint64` max and an empty parent id, and
`kind` and `status_code` map one-to-one onto the record's names.
`status.message` is outside both (`TestCompare_StatusMessageIsOutsideBothForms`).
Both encode nanosecond timestamps as decimal strings for the same 2^53 reason.

## Differences that are design, not defects

- **Projection versus full commitment.** None of the vectors' attribute keys is
  allowlisted, so every record here carries no attributes, and changing any
  non-allowlisted attribute leaves this repo's hash unchanged while changing the
  profile's (`TestCompare_AttributesOutsideTheAllowlistAreNotCommitted`). That is
  the allowlist doing what it is for, and it is also the limit of what the
  record can later prove about a span.
- **Number-typed timestamps are normalised, not refused** on the read path
  (`TestCompare_ReadPathVersusProfileRejects`). The profile rejects them rather
  than coerce. They have to stay readable here for schema v1 and v2 logs.
- **The accumulator does not refuse a zero-tip checkpoint**
  (`TestCompare_AccumulatorDoesNotRefuseZeroTips`); the profile rejects an empty
  batch. The exporter never asks for one: `Shutdown` checkpoints only when tips are
  pending, and the interval trigger needs `pending >= checkpointInterval`. So this
  is a property of `Accumulator.Stage`, not of what the exporter writes, and the
  analogy is loose, since a checkpoint is a delta over sealed traces and not a
  batch from one export request.

## Where this repo's form is the weaker one (run)

These are `TestFinding_*`: they assert today's behaviour and carry the repo's
`BUG(#n)` tag. None is fixed here; each has its own issue. Fixing the first
changes canonical bytes, so it needs a `schema_version` bump and a new fixture
under `CLAUDE.md`'s chain-format discipline. The others change behaviour on
malformed input only, not the bytes of well-formed records.

1. **Attribute types are lost before hashing.** `SpanToRecord` stores
   `AsString()`. An int `1`, a double `1.0` and the string `"1"` produce the same
   record bytes; so do bool `true` and `"true"`, and raw bytes and their base64 text.
   The profile's one-key type tag keeps all seven apart.
   `TestFinding_AttributeTypesCollide` (#58). Reachable for the numeric allowlisted
   keys (`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`). The practical
   cost is low: it is lost evidence of which type a producer sent, not a forgery.
2. **Duplicate attribute keys are first-wins and silent.** The OTLP wire allows
   them; pdata keeps both; the second value never reaches the record. The profile
   rejects. `TestFinding_DuplicateAttributeKeyIsFirstWins` (#59).
3. **Unknown enum numbers collapse to an empty string.** Kinds 6, 7, 9 and 100
   all serialize as `""`, and so do status codes 6, 7, 9 and 100, rather than being
   refused. `TestFinding_OutOfRangeEnumsCollapseToEmpty` (#60).
4. **`GenesisSeed` does not enforce what its comment says.** The comment says it
   errors unless the trace id is "valid lowercase hex (32 hex chars = 16 bytes)".
   It uses `hex.DecodeString`, so an uppercase id seeds the same chain as its
   lowercase spelling while the record bytes differ, and a 4-byte id seeds without
   error. Ids from pdata are lowercase 32-hex or empty (the exporter drops a span
   with an empty trace id), so this is reachable only through a log line.
   `TestFinding_GenesisSeedDoesNotEnforceItsDocumentedIDRule` (#61).
   `canonical.Unmarshal` likewise accepts uppercase and short ids and unknown
   `otel_kind` or `status` names (`TestCompare_ReadPathVersusProfileRejects`).

On the read path `canonical.Unmarshal` does refuse two inputs: a leading-zero
timestamp, which the profile rejects too, and a timestamp past `uint64`, which
the profile accepts (below).

## Where the profile is the weaker or less specified one

**Run** (this repo's tests, against the implementation here):

- **`"0"` and `"-0"` are two encodings of int64 zero.** SPEC allows an optional
  leading `-` and no leading zeros; both pass and hash differently.
  `TestProfileEdge_NegativeZeroIsASecondEncodingOfZero`.
- **No upper bound on timestamps.** `"99999999999999999999999"` passes, though OTLP
  timestamps are `uint64`. `TestProfileEdge_TimestampPastUint64IsAccepted`.
- **Reject precedence and span-core duplicates are unspecified.** An input with two
  defects gets a code that depends on check order, and SPEC defines no order (the two
  references disagree, below). SPEC rejects duplicate *attribute* keys but says
  nothing of a repeated member in the span core, which a last-wins JSON loader, as
  both references use, silently accepts. No vector has two defects.
  `TestProfileEdge_RejectPrecedence`,
  `TestProfileEdge_DuplicateSpanCoreMemberIsLastWins`.
- **`NONFINITE_DOUBLE` is reachable from JSON.** SPEC says it is not, but a literal
  such as `1e999` overflows a double. `TestProfileEdge_OverflowingDoubleLiteralIsNonfinite`.
- **Two spellings of the same base64 bytes.** `QQ==` and `QR==` decode to the same
  byte, and a validator that accepted both would hash them differently. This
  implementation refuses non-zero trailing bits and line breaks, which is stricter
  than SPEC states, so two conforming implementations could differ.
  `TestProfileEdge_NonCanonicalBase64SpellingsDecodeAlikeButHashDifferently`,
  `TestProfileEdge_Base64TrailingBitsAreRejected`,
  `TestProfileEdge_Base64LineBreakIsRejected`.
- **A wrapper that repeats its tag** (`{"s":"a","s":"b"}`) is refused here as
  BAD_WRAPPER. SPEC is silent, and both references would load it last-wins and accept
  it. A choice, not a finding.
  `TestProfileEdge_WrapperWithRepeatedTagIsRejected`.

**Read** (from `canonical.py` and `validate.mjs` at that commit; not executed):

- **The two reference validators disagree outside the vectors.** They are two
  programs, and these inputs separate them:
  - `{"d":9007199254740993}`: Python's `es_number` returns `str(x)` for an `int`, so
    the exact digits are hashed; Node's `String(o)` of the parsed Number gives
    `9007199254740992`, which is also what RFC 8785 requires.
    `TestProfileEdge_DoubleLiteralPast2p53IsRounded` pins the RFC 8785 behaviour of
    the implementation here.
  - `"kind":2.0`: Python's `json` yields a float and rejects; Node's
    `Number.isInteger` accepts it.
  - A span with a bad name and a bad id: Python checks the ids first and reports an
    `ID_*` code; Node checks the name first and reports `BAD_WRAPPER`.
  - `"parent_span_id":null`: Python rejects it (`ID_BAD_LENGTH`); Node accepts it
    (`?? ""`).
  - A JSON `true` timestamp: Python reports `TIMESTAMP_NOT_STRING` (a bool is an
    int); Node reports `TIMESTAMP_NOT_DECIMAL`.
  - A trailing newline: Python's `$` also matches before a trailing newline, so
    `"123\n"` passes as a timestamp and 31 hex digits plus `"\n"` as an id; Node's
    `$` does not. (I confirmed the Python behaviour with the same regex shapes in my
    own snippet, not their code.) `TestProfileEdge_TrailingNewlineIsNotADigitOrHexCharacter`
    pins the SPEC reading here.

  SPEC says the two validators "must agree byte-for-byte on every vector". The
  vectors do not contradict that, and none of these inputs is a vector.
- **The reference does not validate base64 content,** only that the value is a
  string, though SPEC requires RFC 4648 standard alphabet with padding.
- **Pass vectors are fixtures.** The reference harness hashes the shipped bytes
  and checks they re-serialize to themselves; it builds a span from raw fields only
  for the reject cases. `TestProfile_PassVectors_Construction` closes that here.
- **`kv` is spelled two ways.** SPEC shows the canonical form as an object; the
  reject inputs and the reference's input path use a list of `[key, wrapper]`
  pairs, which SPEC does not describe. Both are accepted here.
- **SPEC section 6 and the reference disagree on the catch-all.** SPEC calls
  `BAD_WRAPPER` the code for a "span field structurally malformed (wrong type,
  wrong shape)", but the reference gives a wrong-typed `kind`, `status_code`, id or
  timestamp the named code of its own rule. Read here as the reference does
  (`TestProfileEdge_WrongTypes`).

## Coverage the vectors lack

Found by mutation: each rule below could be removed or weakened while every
vendored vector stayed green. This repo's own tests cover them.

- **The int-attribute format** (`"007"`, `"+5"`, `""`, non-digits). The
  `int-overflow` vector only tests the range.
  `TestProfileEdge_MalformedIntStringIsIntOutOfRange`.
- **Batch sizes other than 3.** The vendored batch has three members, so the
  vectors only exercise subtrees of size 1, 2 and 3. A split rule capped at 2
  agrees with RFC 6962 for all of those and survived them.
  `TestProfile_BatchRoot_AllSmallSizes` checks n = 1 to 66 against a bottom-up
  computation that shares no code with the implementation (it is not an external
  oracle), and `..._SingleSpan` pins SPEC's explicit single-span sentence.
- **Id checks.** The vectors cover uppercase hex and one short `span_id`. Empty ids,
  over-long ids, a lowercase letter outside `a-f` and a short `parent_span_id` are
  not covered. `TestProfileEdge_EmptyAndShortIDs`,
  `TestProfileEdge_NonHexAndOverlongIDs`.
- **RFC 8785 normalising its input.** Every vendored attrs file is already key-sorted
  and number-canonical, so building from them cannot show the normalisation working.
  `TestProfileEdge_AttributeInputIsNormalisedByJCS` feeds reversed key order and
  non-canonical number spellings and requires the published hashes;
  `TestProfileEdge_EquivalentDoubleSpellingsHashAlike` covers the double spellings.
- **A malformed element inside an array wrapper,** and the missing-versus-null
  `parent_span_id` distinction.
  `TestProfileEdge_MalformedArrayElementIsRejected`,
  `TestProfileEdge_ParentSpanIDMissingNullAndEmpty`.

`TestVendoredVectors_MatchProvenance` keeps the vendored files equal to the list in
`PROVENANCE.md`, so an edit to a vector and its `expected.json` together cannot pass.

## Not done

- The reference validators were read, not run, so nothing here shows Python and
  Node disagreeing, only that their source implies it.
- Protobuf ingestion, where `NONFINITE_DOUBLE` is meant to be enforced, is not
  exercised.
- Inclusion proofs, receipts and the transparency-log side of the profile are out
  of scope.
- Only that one commit of the profile was compared.
- A limit of the implementation here, not of the profile: names are hashed after
  `encoding/json` has decoded them, so invalid UTF-8 or a lone surrogate arrives as
  U+FFFD rather than "as given" (`TestProfileEdge_InvalidUnicodeNameIsReplacedBeforeHashing`).

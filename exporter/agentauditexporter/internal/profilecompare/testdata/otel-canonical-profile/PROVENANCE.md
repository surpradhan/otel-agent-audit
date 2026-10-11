# Provenance

These files are a verbatim copy of the conformance vectors for `otel-span/canonical/1`:

- Source: https://github.com/MarkovianProtocol/otel-canonical-profile
- Commit: `4f8c4c5` (2026-08-05)
- Licence: Apache-2.0 (`LICENSE` beside this file, unmodified)
- Copied: 2026-10-11, via the GitHub API at that commit
- Integrity: every file's git blob hash was checked against the hash GitHub reports for
  that commit before it was written (27 files, 19,437 bytes)

Only `LICENSE`, `vectors/expected.json`, `vectors/pass/*` and `vectors/reject/*` are copied.
The profile's SPEC and its Python and Node validators are not vendored and were not executed.

Do not edit these files. They are the oracle; the tests in the parent directory read them as data.
To move to a newer commit, re-fetch all of them together and update the commit above.

## sha256 of each file

```
cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30  LICENSE
24d5d775a0dd5c23d6f5fd3ed6372371d130190ee54dd98ab62545f85d3d4e58  vectors/expected.json
4dc5c4d0acb4725b905bafd0d8736f34b8e007cb170bdd980766ced40c8f05f0  vectors/pass/basic-attrs.attrs.json
f9f83d0baf7cdce210a1943fdd5f6881b8d6aed3d97ded838e4f900ae02d82cf  vectors/pass/basic-attrs.canonical.json
e0934f7272ac523c2da239ae008859975cff1c0a3ea39a83cb39d1e3787ab27c  vectors/pass/bytes-attr.attrs.json
ae8190b3d9c6e8f74c14ba43406df967d2b111d12fcdfb0184bfa9e7f1282ae4  vectors/pass/bytes-attr.canonical.json
8cb54d135ac05060e0000d8bc20d5d1cd7126504542064f914af49796c506ee1  vectors/pass/double-forms.attrs.json
e8e8a08c1aa215d84fda4ccb36b065c359d3b4f41aeadb2034a3bffb2bbfa571  vectors/pass/double-forms.canonical.json
2d25c26d776753a5b9f98b76e667624452d401f2ca3f024b4021a28cb63683b7  vectors/pass/int64-boundary.attrs.json
b01ede5ad10d936e543b8ed65fd50fca8de7b6aeaa7ec79859116229d275e944  vectors/pass/int64-boundary.canonical.json
44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a  vectors/pass/minimal.attrs.json
81d96745dfebfb00594c190fc5d3c10da2427b2738c93cf4bb001dd5f44d5903  vectors/pass/minimal.canonical.json
5d6e0d4e390e001cbca109217ae723cfc6f1256f282bf2daabe02a7e53d83971  vectors/pass/nested.attrs.json
4d19c220b8eb1806da18e02ab121ca4a7a63684923f6baaa277de818afb99e52  vectors/pass/nested.canonical.json
9ad6b3be00c14b75b7c393bacdeacc22eb8e6e58f657ad76368af01b861d19cc  vectors/pass/status-error.attrs.json
704e7112bf2b61eb82efe2f7dad67d8bba6c0d6195aa2cd1a287022e3ea8141e  vectors/pass/status-error.canonical.json
7d0e0a0f036b1def8df2769f6437c71c8d8a4c60a5b334c38733637b4be0288f  vectors/pass/unicode-sort.attrs.json
4c2386f6aab04c76648b8578bc332fa0e5adfdff29a5e926f82f95c483847556  vectors/pass/unicode-sort.canonical.json
79b219991863273fb1db2500f37549b0d08fb953f5c4a23089b115c80667a9a5  vectors/reject/duplicate-attr-key.input.json
9d9754a6fcb2b8049f4fefba20b4d38be3b1f31880caaacaa36512de4a9cdee8  vectors/reject/empty-batch.input.json
f04045ed13a549841d2d611a620cec0b1e726fe9d34d332a7ea46cbfbdc93238  vectors/reject/int-overflow.input.json
560eb469159cb616a609f830b458a63b5b4509c7636b48ffc2cd89fa2988f4c2  vectors/reject/kind-out-of-range.input.json
2e9d31d4bf04b8eadfca4ec658ecff0f807a8e4702ca8ff5985e3683ef77eb16  vectors/reject/short-span-id.input.json
0dd4bf9db037feb14813f6fe0bf08ac7582e2098c50f012db3a11c0e40884385  vectors/reject/status-out-of-range.input.json
736a9155a753677d7c6d7ef69e54c01deaa1396898da5c3e63a6a28ed4c154d3  vectors/reject/timestamp-leading-zero.input.json
6dd8cbd5555e159813078f09cede5aad0501771eccfd307c7dab768e9784b23d  vectors/reject/timestamp-number.input.json
289b90c492e7b3c9fb98ffd9c60d86177aeae55383a0670e980d70b121bb4cd5  vectors/reject/uppercase-hex.input.json
```

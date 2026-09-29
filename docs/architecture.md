# Evidence and implementation boundaries

The reports use three evidence labels:

- **Live verified**: a fresh request was accepted by the server and the response was measured.
- **Sample verified**: a captured input/output or trace was reproduced, but the implementation is not yet independent for the current online version.
- **Static only**: the shape is supported by decompilation or public source, without a live acceptance result in this workspace.

An HTTP 200 with a zero-length body is recorded as an unsuccessful application result. For a header dependency, the key evidence is a one-variable pair: the complete request returns a body, while removing one header returns an empty body under the same time window.

The published hashes identify the trial output without publishing raw responses. They are not reusable authentication material.

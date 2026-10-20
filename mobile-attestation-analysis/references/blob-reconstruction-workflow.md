# Mobile blob reconstruction workflow

## Establish the evidence set

Use the exact application build and at least two sanitized captures when available. Record hashes,
field names, request ordering, sibling-field shapes, timestamps, and whether each value is constant,
session-scoped, request-scoped, or unknown. Strip credentials and customer data before analysis;
keep raw captures in the approved evidence store.

Distinguish platform-backed key attestation from an application-defined field. An X.509 attestation
chain, challenge, and KeyMint authorization list require certificate and policy validation. A JSON
object or encrypted telemetry field assembled by application code is a different protocol even if
its name includes “attestation”.

## Representation before interpretation

Test candidate representations without executing decoded content:

1. direct JSON or UTF-8 text;
2. percent encoding or form encoding;
3. hexadecimal;
4. standard or URL-safe Base64, including omitted padding;
5. documented binary serialization identified by magic or parser callsites.

Several decoders may accept the same characters. Select the representation used by the producer
callsite and corroborate it with expected decoded length. Report character count and decoded byte
count separately.

Compute Shannon entropy only after that decision:

$$H=-\sum_x p(x)\log_2 p(x)$$

Short ciphertext, compressed data, serialized structures, and random identifiers overlap. Entropy
ranks hypotheses; it does not identify an algorithm or origin.

## Trace the producer

Start at the request builder or field insertion and trace backward through:

- final text encoding;
- serialization and field ordering;
- encryption, MAC, or signature API and exact transformation string;
- key, IV, nonce, salt, and associated-data derivation;
- persistent and previous-session state;
- timestamps, counters, random identifiers, device properties, and protection telemetry.

Record actual callsites. Do not attribute the value to a native protection component merely because
that component is present or because a field uses its name. For provider shorthand such as a bare
algorithm name, resolve the transformation actually selected on the observed runtime; do not assume
mode or padding across providers.

## Reconstruct offline

Implement the smallest deterministic model of the observed construction. Inputs must be synthetic
or sanitized and explicit; hidden constants copied from one capture invalidate the model. Separate:

- immutable format constants;
- caller-supplied fields;
- persistent state;
- per-session state;
- per-request freshness;
- environment-derived values that remain unavailable.

For each capture, decode through the observed path, reconstruct the plaintext or serialized form,
then re-encode through the same path. The acceptance criterion is exact byte equality with the
captured field. A correct length, valid padding, readable plaintext, or partial-field match is not
sufficient.

Use a withheld capture when the evidence set permits. A model fitted to one sample cannot prove
which values vary. Preserve failed round-trips because they often expose stale state, wrong encoding,
field ordering, or an incorrect provider default.

## Claim boundaries

Exact round-trip proves equivalence to the observed client-side construction for those captures. It
does not prove that:

- a backend accepts synthetic values;
- the field bypasses device integrity or authentication;
- freshness and anti-replay checks are absent;
- another signed envelope does not bind the request;
- credentials or operation authorization can be replayed.

Do not test those claims against a live service without separate written authorization, an attempt
budget, synthetic accounts/data, and a no-retry client. Report them as unknown when only offline
evidence exists.

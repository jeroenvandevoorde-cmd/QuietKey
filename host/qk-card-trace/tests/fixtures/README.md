# qk-card-trace mock fixture

`mock_trace_v1.txt` is a manually authored HOST parser fixture. It is not a
card capture and carries no card identity, applet byte, APDU, management
material, signer, A2, descriptor, wallet ID or other secret-bearing value.
Its ATR/protocol bytes and `raw_sha256` field are obvious ascending or short
patterns, not observations and not hashes of evidence. Every value is public,
synthetic, permanently NEVER-FUND material.

The fixture exists only to exercise the canonical envelope, deterministic
filename binding, lower-hex field validation and non-echoing summary. A real
trace requires enrolled specimen/apparatus aliases, an outside-Git raw
artifact whose SHA-256 is computed by the later registered procedure, and
separate execution authority.

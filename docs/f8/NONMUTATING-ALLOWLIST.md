# F8 Non-Mutating Allowlist Registrations

EXPERIMENTAL - ACTIVE ZERO-APDU REGISTRATIONS - DEFAULT DENY

## Registration QK-F8-ENROLL-EMPTY-V1

The ring-fenced enrollment tool exposes no PC/SC transmit operation. Every
attempted APDU transmission is refused as `ApduTransmitNotAuthorized`; there
is no passthrough, raw handle, control, attribute, transaction or descriptor-
passing escape hatch. Its complete active APDU set is empty.

Once the photograph and apparatus evidence prerequisites are complete, one
invocation may perform only this ordered non-APDU sequence:

1. bounded reader enumeration;
2. exclusive connection to the exact selected registered reader;
3. one explicit reset;
4. exact ATR capture;
5. negotiated-protocol capture; and
6. disconnect.

The HOST harness caps are exactly 4,096 reader-list bytes, 32 readers, 255
bytes per reader name, one selected specimen per invocation, the safe wrapper's
33-byte ATR maximum, and 16,384 canonical transcript bytes. They are enrollment
tool controls only and select no QK-LIM-APDU, session or product value.

The canonical result is a `QK-CARD-ENROLLMENT-V1` LF-terminated ASCII
transcript as specified in `ENROLLMENT-MANIFEST.md`. It states zero APDU request
and response counts. Every reader-name and ATR byte is recorded as complete
lowercase hex, one octet per pair, without redaction or normalization. The tool
never persists automatically.

## Registration QK-F8-G0-EMPTY-V1

This is the complete live APDU allowlist registered for the existing
`host/qk-card-trace` mock boundary:

| Order | Command bytes or exact mask | Purpose | Permitted response |
|---|---|---|---|

NONE - ZERO LIVE APDU COMMANDS ARE APPROVED.

The matching code table in `host/qk-card-trace/src/allowlist.rs` has length
zero. The checker rejects `mode=LIVE` and returns `ApduRecordNotAuthorized` for
either APDU record type in its mock envelope. It therefore accepts no live
command or response and makes no live-trace format decision.

## Denied operations

Every APDU is denied, including `SELECT`, `GET DATA`, `GET STATUS`,
GlobalPlatform management, application commands and undocumented commands.
Mutation, personalization, authentication, applet loading or deletion,
provisioning, signing, RNG sampling, retries and exploratory follow-ups are not
authorized. The two commands in `ARRIVAL-ALLOWLIST-DRAFT.md` are an inactive
candidate only and alter neither active registration.

Cold/warm reset, ATR capture and negotiated-protocol capture are transport
observations rather than APDU commands. Their classification does not grant a
physical run. The offline parser's caller-supplied controls and the enrollment
harness caps are HOST controls only; all QK-LIM-APDU values remain open.

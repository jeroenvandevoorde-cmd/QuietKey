# Campaign 034 - bounded IFSD-254 readback

Status: PREREGISTERED - qualifying runs not yet executed.

## Boundary and fixed recipe

QK-DEC-167-SUP-007 requalifies only `qk_t1` and `qk_sec1210_wire`.
The other 52 registered corpus roots remain byte-frozen and replay-only.
The new corpus seeds are public synthetic IFS and framing inputs; no card,
UART, GPIO, bench code, wall clock or signing operation enters either closure.
The existing default T=1 oracle and joint paths remain exercised alongside
the explicit IFS state/bound oracle and negotiated joint path.

Both 100,000-input runs and every minimization pass must use one published
code commit, recorded as the qualification source in the completed record
and both final manifests. Until qualification completes, the active manifests
and checker registrations retain Campaign 033 unchanged. The new seed bytes
below are materialized only for the qualifying runs, then the measured fixed
points replace the selected roots and registrations together.

| Target | Public seed | Maximum input bytes | Feature, defaults disabled |
|---|---:|---:|---|
| `qk_t1` | 167007 | 8,192 | `t1-readback` |
| `qk_sec1210_wire` | 167008 | 4,096 | `sec1210-wire` |

Pinned tools: cargo-fuzz 0.13.2; nightly-2026-08-25;
rustc `1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release overflow checks and debug assertions; offline dependency resolution;
two-second per-input timeout; 2,048 MiB RSS ceiling; reload disabled;
final statistics; empty target artifact directories before the runs.

```text
fuzz/run-bounded.sh qk_t1 100000
fuzz/run-bounded.sh qk_sec1210_wire 100000
```

Every exact post-run root is retained and copied independently twice. Both
copies are minimized with the existing `fuzz/minimize-corpus.sh`; each pass,
exit and identity is recorded. Promotion requires agreeing fixed points and
one unchanged confirmation pass. No unselected root is promoted or modified.
Corpus figures are measured file counts and bytes, not libFuzzer's live-unit
count. All failures and artifacts remain preserved and are not erased by a
later passing run.

## Retained prior identities

Campaign 033 and its evidence are unchanged. Both prior manifests bind
`8664809b7968d63c5f227492e7aa2984a3b1c604`.

| Target | Prior corpus files/bytes | Prior manifest bytes/LF | Manifest SHA-256 | Prior entries SHA-256 |
|---|---:|---:|---|---|
| `qk_t1` | 449 / 9,626 | 63,131 / 456 | `6ab48898389737cb95af244a631dda12e63a4e72f0066235aada8625791c1e24` | `106558d28ca7402958fa0cd09a9b9ec5f267b17b904ae9568ab292f29aa04b97` |
| `qk_sec1210_wire` | 283 / 25,884 | 45,707 / 290 | `749cd341d7833f27e227cfa1aae620d453736516bda14610d18cf4493c259cc1` | `2e2d17e146946d08c2b1007e807159ee521a91b17de09f7cdc01ea21230ae6fc` |

## Exact starting points

Before qualification, 42 new public T=1 seeds / 1,309 bytes and 31 new wire
seeds / 1,410 bytes were added to the retained roots. They exercise the exact
echo and request; corrupt NAD, LRC, INF and LEN; I/R/WTX/RESYNCH/ABORT and card
IFS substitutions; repeated negotiation and unsolicited echo; pre-activation
258-byte blocks and post-activation 259-byte blocks; the independent wire
258/259/261/262-byte payload boundary; fragmentation, events and deadlines.
Their exact bytes and filenames are registered below, not yet promoted into
the active corpus registry by this preregistration commit. The
canonical listing is sorted `SHA-256<TAB>bytes<LF>`; manifest entries retain
the corresponding corpus paths.

| Target | Start files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_t1` | 491 / 10,935 | 33,257 | `bfcb7bf86647f63d42d550af22fd011188adf9d950b80341ea2d66692146dbe1` | `b542e9faa8a2d7f770e9ead5e124038f3a097343c76731e5aaef0749e711e85f` |
| `qk_sec1210_wire` | 314 / 27,294 | 21,381 | `2344066d15dc1d128767b00bfff50b92b281459649fcde4cea89beab6b66619e` | `f9bc54e38db00c2c7230f11f502cc8692e94e3b43b3e931296dec23f2d7c8092` |

## Reproducible added seed bytes

Each file is placed under `fuzz/corpus/<target>/<filename>` for the runs.
The filename is SHA-1 of the bytes for libFuzzer corpus naming only; SHA-256
listings and manifest entries above are the evidence identities. Baseline and
added bytes are retained independently before any qualification or promotion.

| Target | Filename | Bytes | Hex |
|---|---|---:|---|
| `qk_sec1210_wire` | `c3d3ea8105b523836b93c99408c0bcdf34ca7050` | 18 | `03066f05000000000400000000c101fe3e6b` |
| `qk_sec1210_wire` | `fda1a564cb25ba713cc2463f31e2448ec81df6e2` | 18 | `03068005000000000400000000e101fe1e84` |
| `qk_sec1210_wire` | `446f07f496a76301d89e3c6524b686872a30c84a` | 18 | `03068005000000000400000000e101fe1f85` |
| `qk_sec1210_wire` | `daf5ff432d889f668cb415647793dca5c2b332b2` | 18 | `03068005000000000400000001e101fe1f84` |
| `qk_sec1210_wire` | `65ed2bf8eac98a4c4bdb25454f13ca7a060378a0` | 18 | `03068005000000000400000000e101fd1d84` |
| `qk_sec1210_wire` | `176d8488408f86b63196606efd57dbcc7b70b1a0` | 18 | `03068005000000000400000000c101fe3e84` |
| `qk_sec1210_wire` | `714fcb61bd923b53405ee7151d5b688360b83fb8` | 271 | `0306800201000000040000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a82` |
| `qk_sec1210_wire` | `3355ca7630cb831c89c30fc54ae8517f9341d9d0` | 272 | `0306800301000000040000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5ad9` |
| `qk_sec1210_wire` | `fc18043d6bae1e372ea7722ecd1106132c5c5921` | 274 | `0306800501000000040000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5adf` |
| `qk_sec1210_wire` | `23c317ee94eddac402f26d2d795d73be726f5a77` | 275 | `0306800601000000040000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a86` |
| `qk_sec1210_wire` | `0c24ed4652d46eaf3cdf3595358bdbbcbb97ad85` | 10 | `00000000000043000000` |
| `qk_sec1210_wire` | `4f86eb766a597d52b24f4c379935a02cab8d8237` | 10 | `00000000010043000800` |
| `qk_sec1210_wire` | `097675049fa62e0610eed86bd77b2deccb9c11f8` | 10 | `00000000000143010803` |
| `qk_sec1210_wire` | `bd6e89c8adcd37a1390f9e839ee50a753405e3bb` | 10 | `00010000000043000000` |
| `qk_sec1210_wire` | `9964f3e4101baefc7cd2af7b33c5fd1f48ee00ae` | 10 | `00010000010043000800` |
| `qk_sec1210_wire` | `fc47cd85e73aa48a2e271b9f7bdaeb9aa4b5eb5a` | 10 | `00010000000143010803` |
| `qk_sec1210_wire` | `733def7d438ef26490c219f45dbeb9eac3a7f589` | 10 | `00020000000043000000` |
| `qk_sec1210_wire` | `23942090218a12f4469e10ea467d20423a6b573d` | 10 | `00020000010043000800` |
| `qk_sec1210_wire` | `5d5424e4b32307a52d77c416987dc5346d07bbe6` | 10 | `00020000000143010803` |
| `qk_sec1210_wire` | `10d37177dd2110b2ec61486a3e3f8424469d71f6` | 10 | `00030000000043000000` |
| `qk_sec1210_wire` | `c8787fcd0627e3872034fe27003008d7c34b5130` | 10 | `00030000010043000800` |
| `qk_sec1210_wire` | `bb60fd7336a79c9f1dce782c948c8e8c2e272b5b` | 10 | `00030000000143010803` |
| `qk_sec1210_wire` | `bb05d048c26708c3768950342ef95a0eec190dc2` | 10 | `00040000000043000000` |
| `qk_sec1210_wire` | `ffff53833b4eee82e2939488fd870bdea659c852` | 10 | `00040000010043000800` |
| `qk_sec1210_wire` | `26dd0f55d9f0b01d4bf12f0f576bec8454c39a8c` | 10 | `00040000000143010803` |
| `qk_sec1210_wire` | `3790f1a1f90901ec3a81d5fac172a376182b5df0` | 10 | `00050000000043000000` |
| `qk_sec1210_wire` | `069ef838077cc350e45a4f0aa564eba3d52c78c2` | 10 | `00050000010043000800` |
| `qk_sec1210_wire` | `7a1a5a5f41e916bc5458250ca62425668465b2e6` | 10 | `00050000000143010803` |
| `qk_sec1210_wire` | `1ec284c0c82b49b08e7a6dc976984227b99d2f9f` | 10 | `00060000000043000000` |
| `qk_sec1210_wire` | `cc294f3fa7ec72079b55b5cf4a8e33c3ebb327e9` | 10 | `00060000010043000800` |
| `qk_sec1210_wire` | `ec00dd7ba768abfee94f5805fc34c58047dd3a23` | 10 | `00060000000143010803` |
| `qk_t1` | `ea2ad1f4757f997e1611d679919b8a140014ff7a` | 5 | `00e101fe1e` |
| `qk_t1` | `164cc821854cf992857ea9516af36919956d7b72` | 5 | `00c101fe3e` |
| `qk_t1` | `9359265edbb7f9ae10f036256665fb758781675f` | 5 | `01e101fe1f` |
| `qk_t1` | `51a658bbd0947d044dfc15f12b45333af5f3727b` | 5 | `00e101fe1f` |
| `qk_t1` | `d2799c480d322ba6a1f2b0f26ee446dfe7de388e` | 5 | `00e101fd1d` |
| `qk_t1` | `bf921a1682c38d29ca12d04abe77839ae45de589` | 4 | `00e100e1` |
| `qk_t1` | `097cc96792703a4563719ae293b502649c4b9efe` | 5 | `00c30101c3` |
| `qk_t1` | `871d4633ab51af629c02b4baf1c5497d2dc92bc6` | 4 | `00800080` |
| `qk_t1` | `f0c957104bb1b80c9d125d9c8cbb3f06fbf2ab1a` | 4 | `00000004` |
| `qk_t1` | `00e14c6ef59816760e2c9b5a57157e8ac9de4012` | 4 | `00000005` |
| `qk_t1` | `d851ce5405c1bd5dc5bf9c21c3962cc75bd19347` | 4 | `01000004` |
| `qk_t1` | `05fce3edd1f2389b3663805393f49605dcdd9233` | 4 | `01000005` |
| `qk_t1` | `e826792100dd0807fa216ac6d195031c7ddc465c` | 4 | `02000004` |
| `qk_t1` | `bde52fefc407c08467f15d5eb86ca1ead9ddfa59` | 4 | `02000005` |
| `qk_t1` | `a3585b70f1c7ffbdec10f6dadc964336118485c4` | 4 | `03000004` |
| `qk_t1` | `15c2d2bc87f1d9347f7ab284be3403d28c0a5ab7` | 4 | `03000005` |
| `qk_t1` | `bd3450c274d77562d74370a664ab8dde06d57690` | 4 | `04000004` |
| `qk_t1` | `31c9e9a74071accb3a989935af45b755947b5f26` | 4 | `04000005` |
| `qk_t1` | `a92938f5bfb0508f992d61b088c1df753f154c93` | 4 | `05000004` |
| `qk_t1` | `ec65cc7c547c56af56966b35cdf8431ea5fc3d78` | 4 | `05000005` |
| `qk_t1` | `c7481e4b984bcfba8416d3c8bac3ce06194cb8c7` | 4 | `06000004` |
| `qk_t1` | `16599d744887ff665dc40ab30c4e93c2aa6fc98d` | 4 | `06000005` |
| `qk_t1` | `6e6e41a755185e3de17798edaae25bda87441606` | 4 | `07000004` |
| `qk_t1` | `bafa3ddad98e138f99158a468f42a98c33ddb946` | 4 | `07000005` |
| `qk_t1` | `2a4336b131a63f8cd820ee41b3058836eacf8a28` | 4 | `08000004` |
| `qk_t1` | `147d21457d5bb810d2dcaef123ec3b463f674ec1` | 4 | `08000005` |
| `qk_t1` | `6a83ed8d8dcbeb78629fe498718a09eb6cc8ca1d` | 4 | `09000004` |
| `qk_t1` | `d626b493e6c20b3bf9c7f6d24828e20a39313460` | 4 | `09000005` |
| `qk_t1` | `ccf42a004ca555598a9a345745fb6730c4c9a879` | 4 | `0a000004` |
| `qk_t1` | `c5a9d0e4c1e078a4bdc4ddb3914a8a7b53919c5d` | 4 | `0a000005` |
| `qk_t1` | `1b45ac8cae59548263a1dc9db13c455977c63b5e` | 4 | `0b000004` |
| `qk_t1` | `98398e7e13a4055f8e60c71191dc1680cd7ae387` | 4 | `0b000005` |
| `qk_t1` | `494f52f1be6dd0465caee84f2fc7e2a277e694ef` | 32 | `0000000002000000030000000400000001000000020000000300000006000000` |
| `qk_t1` | `0291c307c319ecb263e324ea55c51c5e65fd5074` | 36 | `000000000200000003000000040000000100000002000000030000000600000000000000` |
| `qk_t1` | `554e25a59437e050fa55ce1b3bf16cc958430aab` | 36 | `000000000200000003000000040000000100000002000000030000000600000004000000` |
| `qk_t1` | `3bffea93183633ba53161ebf33ef50b40527bc77` | 36 | `000000000200000003000000040000000100000002000000030000000600000007000000` |
| `qk_t1` | `27ed9c15ac9ae4748f6c0e6cdf07f32c561c8f3b` | 36 | `0000205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a20` |
| `qk_t1` | `afdc2c9b9e6a7fe1e721957500e4356a104fb8c3` | 37 | `0000215a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a7b` |
| `qk_t1` | `fb1fc92488e3956acecd480ca4f73784a2a1709a` | 222 | `0000da5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5ada` |
| `qk_t1` | `e4feef3791e8d5853086d888b8f3ec81dc6d7fde` | 223 | `0000db5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a81` |
| `qk_t1` | `a4fc8186ccdc6fa7696bda2ca82e703f5eb8eaa6` | 258 | `0000fe5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5afe` |
| `qk_t1` | `63801b41dc524ff996c98c9b017438b913383ad4` | 259 | `0000ff5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5aa5` |

## Results

Pending the published-source runs, two-copy minimizations, promotion and
complete replay. No qualification, physical sitting or Gate claim is made
by this preregistration.

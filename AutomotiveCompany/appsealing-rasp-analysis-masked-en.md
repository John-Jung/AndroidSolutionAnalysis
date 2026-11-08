# Commercial RASP (AppSealing-class) Detection Mechanism Analysis

> This document is a technical analysis with vendor/app identifiers masked. The target app and company names are replaced with `[TARGET_APP]` / `[VENDOR]`, etc.

## 1. Target Information

| Item | Value |
|---|---|
| App | `[TARGET_APP]` (`[PACKAGE_NAME]`) |
| Device | `[DEVICE]`, Android 10, arm64, Magisk-rooted |
| Objective | Traffic capture → server-side API vulnerability research (bug bounty) |
| Protection | Commercial RASP (AppSealing-class, `[VENDOR]`) |
| Detection core | `libdxbase.so` (arm64 split APK, ~515KB) |

## 2. Protection Solution Identification

- Global Java string encryption `[VENDOR_PKG].dc.mXXXX()` confirmed → commercial RASP signature
- Among `.so` files, detection-core candidate identified: TEE module (unrelated), **detection core `libdxbase.so`**, crypto helper
- Confirmed via imports: `pthread_create` (watchdog), `open/read/openat/opendir/readdir` (proc·maps scan), `access` (root files), `syscall` (libc bypass), `abort/exit/kill`
- Excluded as noise: crash-reporting SDK's `isRooted` (device metadata collection, not enforcement)

## 3. Static Analysis Walls

| Attempt | Result |
|---|---|
| String back-tracing | Strings encrypted (0 plaintext detection strings, runtime-decrypted via `FUN_00124124`) |
| thunk XREF back-tracing | Caller untraceable due to GOT indirect calls |
| Ghidra image base | 0x100000 (runtime offset + 0x100000 = Ghidra address) |

## 4. Dynamic Pre-emption Analysis Technique (Key Breakthrough)

With static analysis blocked, **frida load pre-emption** was used to recover detection-thread addresses at runtime:

1. Hook `android_dlopen_ext` / `__loader_android_dlopen_ext` → catch the moment the detection `.so` loads
2. At load time, obtain `JNI_OnLoad` (base+0x1bc20) and import PLT slots
3. Attach globally to `libc!pthread_create`, **filtering only calls whose return address falls within the detection `.so` range** → extract every detection-thread start-routine address

**Caveat:** Overwriting GOT slots directly (`writePointer`) crashes frida-agent → only `Interceptor.attach` + args modification is safe. Replacing exit-function slots with dummies triggers the cross-check (below) and backfires.

## 5. Full Detection-Thread Map

| start_routine (base+) | Ghidra addr | Role | Calls exit |
|---|---|---|---|
| +0x37ab4 | 0x137ab4 | 7-way file-existence check (fopen/open/stat/lstat/access/glob) — root files | No (returns result) |
| +0x3fcd0 | 0x13fcd0 | Directory CRC32 blacklist — root-app detection | No |
| +0x59a8c | 0x159a8c | Encrypted-path file parsing (key search, maps suspected) | No |
| +0x5a020 | 0x15a020 | Read file, extract field before `:` | No |
| +0x413ac | 0x1413ac | **Watchdog — self-check + CallSupervisor exit** | **Yes (svc)** |
| +0x414bc/d0 | 0x1414d0 | **frida timing anti-debug core** | (via handler) |
| verdict +0x2a924 | 0x12a924 | App path / package-name integrity check | No |

Each detection function only "performs detection + records result into a param struct"; termination is carried out by the watchdog/handler.

## 6. Core Anti-Frida Mechanisms

### (1) Timing Measurement
```
uVar2 = cntvct_el0;        // ARM cycle counter
CallSupervisor(0);          // direct svc (maps open/read, bypasses libc)
uVar3 = cntvct_el0;
if (0x465000 < uVar3-uVar2) // >4.6M cycles = slowed by hooking = detected
    (DAT_00187aa0 ^ 0xbe8acff5)(...);  // call response handler
```
If frida's hooking overhead slows the svc, it is detected. **Detects frida's mere presence via timing.**

### (2) Probabilistic Termination Handler (FUN_0011e6e8 = DAT_00187aa0 ^ 0xbe8acff5)
```
uVar1 = (stack_addr ^ cntvct_el0) ^ 0x11e6f8;
uVar1 = xorshift(uVar1) & 3;    // pseudo-random 0~3
if (uVar1==3) return;           // 1/4 pass
if (uVar1==1) return;           // 1/4 pass
if (uVar1==2) return;           // 1/4 pass
CallSupervisor(0); do{CallSupervisor(0);}while(1);  // only 1/4 terminates
```
Even when detected, terminates with **only 1/4 probability** → destroys reproducibility to confuse the reverser. This is the cause of the "same conditions, yet sometimes alive sometimes dead" irregularity.

### (3) Function-Pointer Obfuscation
The response-handler address (0x11e6e8) is XOR-encoded with `^ 0xbe8acff5` and stored in `DAT_00187aa0` (set in `_INIT_2` at 0x11e0d0). Restored via XOR at runtime.

### (4) Self-Check Watchdog (FUN_001413ac)
```
local_48 = DAT_00187c18 ^ 0x40000;        // expected value pre-computed
pthread_create(FUN_001414bc);              // actual detection thread
pthread_join;                              // wait for completion
if (local_44==0 || local_48 != DAT_00187c18)  // if detection thread didn't run properly
    CallSupervisor(0); do{...}while(1);    // svc exit
```
Reverse-verifies that the detection thread changed `DAT_00187c18` as expected. Replacing the detection thread with a dummy leaves this value unchanged → termination → **the reason simple thread-killing failed.** Additionally, `DAT_00187a64 < 3` allows **up to 3 self-regenerations** (revives even when killed).

### (5) Direct svc Termination
All termination is done via `CallSupervisor` (inline svc #0) → all libc `exit`/`kill`/`syscall` wrapper hooks are nullified.

## 7. Conclusion: frida Runtime Bypass Is Infeasible

Structurally impossible to bypass with frida:
1. **Timing-based** — frida hooking overhead inevitably exceeds `0x465000` → detected
2. **Probabilistic termination** — even a "pass" dies on the next run → no stable bypass
3. **Direct svc** — all libc hooks nullified
4. **Self-check + self-regeneration** — killing the thread revives it; faking non-kill trips the self-check

## 8. Bypass-Path Analysis

### Only realistic path = static patching
- NOP all timing-comparison branches (`0x465000` cmp) in the detection `.so`
- NOP the FUN_001413ac self-check exit branch
- NOP the FUN_0011e6e8 probabilistic-exit branch
- **self-CRC (self-integrity check) verification needed** ← incomplete
- Repackage + re-sign the APK

### Alternative (cntvct_el0 manipulation) — effectively infeasible
- Stalker instruction rewriting: memory modification risks memory-based self-CRC + Stalker overhead self-detonates the timing check
- Timer-value manipulation: `mrs cntvct_el0` is a direct EL0 register read, requiring kernel privilege (CNTKCTL_EL1 trap) → impossible with frida alone

### Server-verification risk (unconfirmed)
- As a high-security app, **server-side Play Integrity / APK hash verification** is likely
- Client-side self-CRC/self-signature can be bypassed by patching, but server verification makes local patching meaningless
- Shamiko root-hiding **failed** (RASP root detection not concealed at the Zygisk level)

## 9. self-CRC Analysis Status (In Progress)

- CRC32 table: `DAT_0010b1a4` (standard CRC32, starts at `0x10b1a8` with `0x77073096...`)
- 84 table references concentrated in one function, `FUN_0011a370` (unrolled CRC-computation loop)
- `FUN_0011a370` is a large composite function mixing CRC + formatting + floating-point
- Expected-CRC comparison point: `DAT_00185328 == uVar22`
- **Unconfirmed:** whether this CRC is self-CRC (targeting own `.so`/`.apk` bytes) vs. app-blacklist CRC → `DAT_00185328` XREF back-tracing needed

## 10. Next Steps (choose one)

1. **Continue self-CRC verification** — determine the CRC's verification target via `0x185328` XREF
2. **Verify server validation first** — capture login/API traffic on a clean device, check for Play Integrity token transmission (pre-determine whether patching will pay off)
3. **Wrap up analysis** — finalize current analysis as a RASP asset, defer patching

**Recommendation:** Option 2 (verify server validation first) — since hitting a server wall after completing static patching would be wasted effort, determining the presence of server-side integrity verification first is more efficient.

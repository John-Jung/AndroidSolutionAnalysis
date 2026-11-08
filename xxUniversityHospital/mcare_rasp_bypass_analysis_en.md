# Medical Institution Mobile App — AppIron RASP Root Detection Bypass Analysis

> This document is written with the specific medical institution name, package, and developer identifiers masked.

## 1. Target Information

| Item | Detail |
|---|---|
| Package | `com.XXXX.mcare.XXXX` |
| App | ○○ Hospital mobile care app (developer: XXXX) |
| Device | Samsung Galaxy Note9 (SM-N960N), Android 10, arm64, rooted |
| Goal | Capture HTTPS traffic with Burp — requires getting the app to run normally |
| Detection solution | AppIron (AIMTREE commercial RASP) + app's own Java root check |

## 2. Detection Solution Identification

Commercial security modules confirmed in APK `lib/arm64`.

| File | Role |
|---|---|
| `libAppIron-jni_v2.13.28.so` | AppIron RASP — native integrity/root/frida detection |
| `libEdgeCrypto.so` / `libEdgeSCSP.so` | Encryption / secure communication |
| `libionepass.so` (`kr.co.ideatec.ionepass`) | FIDO authentication |
| `libsqlcipher.so` | DB encryption |

The Java source contained no `/proc/self/maps` or `TracerPid` references, confirming that the **core detection is implemented natively**.

## 3. Detection Structure — Two Independent Layers

Analysis showed detection split across two independent layers.

### Layer 1 — Native (libAppIron)
`libAppIron-jni.so` spawns a watchdog thread at process init and performs:
- Root file detection: `faccessat("/system/app/Superuser.apk")`, `/system/xbin/su`, etc.
- `su` execution attempt: `Runtime.exec("su")`
- `/proc/self/maps` scan → detects frida-agent traces
- `/proc/<pid>/status` full process enumeration + TracerPid anti-debug
- Execute-only (XOM) memory mapping → anti-Frida (obstructs backtracing)
- On detection, calls `_exit(0)` directly at `libAppIron +0xbd4c`

### Layer 2 — App Java Code
`XXXXCommonActivity.onStart()` performs an independent root check.
```java
protected void onStart() {
    super.onStart();
    try {
        RealizationOfJustice.isRooting();   // throws if rooted
    } catch (MCareFrameworkException e) {
        startActivity(getNotifyIntent(..., ACTION_APP_KILL, ...));  // popup → kill
    }
}
```
On root detection it throws `MCareFrameworkException`, and the catch block launches the warning popup activity (`XXXXNotifyPopupActivity`) via the `MCARE_ACTION_APP_KILL` action, then terminates.

### Integrity Verification Flow (Loading Gate)
`InitializeAppLoadingUseCase` calls `AppIronRepository.startAppIron()` during app loading and uses the result (`AppIronResult`) to decide whether loading proceeds.
```kotlin
sealed interface AppIronResult {
    object Success : AppIronResult          // verification success → loading proceeds
    data class Error(errorMessage: String)  // verification failure → loading halts
}
```
- Implementation: `com.XXXX.mcare.data.repository.LocalRepositoryImpl.startAppIron()`
- In a rooted environment it returns `Error` → "Checking integrity" infinite loading

## 4. Analysis Process (Diagnostic Path)

Each detection vector was identified sequentially via Frida dynamic analysis.

| Step | Finding |
|---|---|
| frida-trace spawn | Immediate self-kill (native init stage) |
| libc file-access hook | `access("Superuser.apk")` detection confirmed |
| File bypass attempt | Detection uses **`faccessat`**, not `access` (Android 10) |
| Termination trace | frida-agent **XOM SIGSEGV** → anti-Frida confirmed |
| Rename + port change | Process-name/port detection passed |
| maps trace | frida-agent exposed via `/proc/self/maps` scan |
| `_exit` caller trace | Termination point pinned at **`libAppIron +0xbd4c`** |
| Ghidra static analysis | `FUN_001096d0` — scans file strings then calls `_exit(0)` |
| dumpsys | Popup = `XXXXNotifyPopupActivity`, action `MCARE_ACTION_APP_KILL` |
| jadx reverse-trace | `XXXXCommonActivity.onStart` → `RealizationOfJustice.isRooting()` |
| Find Usage | Impl `LocalRepositoryImpl`, caller `InitializeAppLoadingUseCase` pinned |

Key takeaway: pinning the native termination point via `_exit` caller tracing, then reverse-tracing the Java layer with dumpsys and jadx to **separately identify the two layers**, was the prerequisite for the bypass.

## 5. Final Bypass (bypass-localrepo.js)

Neutralizes three points simultaneously.

### (1) Neutralize Java Root Check
Hook `RealizationOfJustice.isRooting()` to return normally without throwing → blocks the onStart popup+kill path.
```javascript
var ROJ = Java.use("com.XXXX.mcare.new_framework.util.RealizationOfJustice");
ROJ.isRooting.overloads.forEach(function(ov){
    ov.implementation = function(){ return; };
});
```

### (2) Force Integrity Verification Success
Hook `LocalRepositoryImpl.startAppIron()` to always return `AppIronResult.Success` → `InitializeAppLoadingUseCase` proceeds with loading normally.
```javascript
var Success = Java.use("com.XXXX.mcare.domain.model.result.AppIronResult$Success");
var Impl = Java.use("com.XXXX.mcare.data.repository.LocalRepositoryImpl");
Impl.startAppIron.overloads.forEach(function(ov){
    ov.implementation = function(cont){
        return Success.INSTANCE;
    };
});
```

### (3) Block Native Termination (Safety Net)
On libAppIron load, neutralize libc `_exit`/`exit`/`abort` → defends against native watchdog termination.
```javascript
var iv = setInterval(function(){
    var b = Module.findBaseAddress("libAppIron-jni_v2.13.28.so");
    if(b){ clearInterval(iv);
        ["_exit","exit","abort"].forEach(function(n){
            var p = Module.findExportByName("libc.so", n);
            if(p) Interceptor.replace(p, new NativeCallback(function(c){}, 'void', ['int']));
        });
    }
}, 10);
```

## 6. Why the Bypass Succeeded

| Layer | Detection method | Bypass point | Effect |
|---|---|---|---|
| Java onStart | `isRooting()` exception | method → void return | removes popup/kill |
| Integrity gate | returns `Error` | `startAppIron` → Success | resolves infinite loading |
| Native watchdog | direct `_exit` call | libc exit replace | defends against force-kill |

The key was **cutting at the Java layer rather than fighting the native code**. AppIron's native detection (maps/XOM/ptrace) is hard to outrun with runtime hooking, but the final verdict surfaces to Java through a Kotlin wrapper (`LocalRepositoryImpl.startAppIron`), so returning `Success` at that point **lets the native detection run while nullifying only its result**. Native `_exit` blocking acts as a supplementary safety net.

## 7. Next Step (Traffic Capture)
With the app running normally, HTTPS can be captured via Burp proxy using the rooted phone's system CA. SSL pinning presence must be verified against actual traffic.

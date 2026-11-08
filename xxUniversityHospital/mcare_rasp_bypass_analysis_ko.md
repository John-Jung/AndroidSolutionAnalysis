# 의료기관 모바일 앱 — RASP 루팅 탐지 우회 분석

> 본 문서는 특정 의료기관 명칭·패키지·개발사 식별자를 마스킹하여 작성함.

## 1. 대상 정보

| 항목 | 내용 |
|---|---|
| 패키지 | `com.XXXX.mcare.XXXX` |
| 앱 | ○○병원 모바일 진료 앱 (개발사: XXXX) |
| 기기 | Samsung Galaxy Note9 (SM-N960N), Android 10, arm64, 루팅됨 |
| 목표 | Burp로 HTTPS 트래픽 캡처 — 이를 위한 앱 정상 실행 |
| 탐지 솔루션 | AppIron (AIMTREE 상용 RASP) + 앱 자체 Java 루팅 체크 |

## 2. 탐지 솔루션 식별

APK `lib/arm64`에서 상용 보안 모듈 확인됨.

| 파일 | 역할 |
|---|---|
| `libAppIron-jni_v2.13.28.so` | AppIron RASP — 네이티브 무결성/루팅/frida 탐지 |
| `libEdgeCrypto.so` / `libEdgeSCSP.so` | 암호화 / 보안통신 |
| `libionepass.so` (`kr.co.ideatec.ionepass`) | FIDO 인증 |
| `libsqlcipher.so` | DB 암호화 |

Java 소스에 `/proc/self/maps`, `TracerPid` 등이 전혀 없어 **탐지 핵심이 네이티브에 구현**됨을 확인함.

## 3. 탐지 구조 — 2중 레이어

분석 결과 탐지가 서로 독립된 두 레이어로 구성됨.

### 레이어 1 — 네이티브 (libAppIron)
`libAppIron-jni.so`가 프로세스 초기화 시 워치독 스레드를 띄우고 다음을 수행함.
- 루팅 파일 탐지: `faccessat("/system/app/Superuser.apk")`, `/system/xbin/su` 등
- `su` 실행 시도: `Runtime.exec("su")`
- `/proc/self/maps` 스캔 → frida-agent 흔적 탐지
- `/proc/<pid>/status` 프로세스 전수조사 + TracerPid anti-debug
- 메모리 execute-only(XOM) 매핑 → anti-Frida (백트레이싱 방해)
- 탐지 시 `libAppIron +0xbd4c`에서 `_exit(0)` 직접 호출

### 레이어 2 — 앱 Java 코드
`XXXXCommonActivity.onStart()`에서 독립적으로 루팅 체크함.
```java
protected void onStart() {
    super.onStart();
    try {
        RealizationOfJustice.isRooting();   // 루팅이면 예외 throw
    } catch (MCareFrameworkException e) {
        startActivity(getNotifyIntent(..., ACTION_APP_KILL, ...));  // popup → kill
    }
}
```
루팅 탐지 시 `MCareFrameworkException`을 던지고, catch에서 `MCARE_ACTION_APP_KILL` 액션으로 경고창 액티비티(`XXXXNotifyPopupActivity`)를 띄운 뒤 종료함.

### 무결성 검증 흐름 (로딩 게이트)
`InitializeAppLoadingUseCase`가 앱 로딩 중 `AppIronRepository.startAppIron()`을 호출하고, 결과(`AppIronResult`)로 로딩 진행 여부를 결정함.
```kotlin
sealed interface AppIronResult {
    object Success : AppIronResult          // 검증 성공 → 로딩 진행
    data class Error(errorMessage: String)  // 검증 실패 → 로딩 중단
}
```
- 구현체: `com.XXXX.mcare.data.repository.LocalRepositoryImpl.startAppIron()`
- 루팅 환경에서 `Error`를 리턴 → "무결성 확인 중" 무한 로딩

## 4. 분석 과정 (진단 경로)

Frida 동적 분석으로 각 탐지 벡터를 순차 식별함.

| 단계 | 발견 |
|---|---|
| frida-trace spawn | 즉시 self-kill (네이티브 초기화 단계) |
| libc 파일접근 후킹 | `access("Superuser.apk")` 탐지 확인 |
| 파일 우회 시도 | 탐지가 `access`가 아닌 **`faccessat`** 사용 (Android 10) |
| 종료 추적 | frida-agent **XOM SIGSEGV** → anti-Frida 확인 |
| 리네임+포트변경 | 프로세스명/포트 탐지는 통과 |
| maps 추적 | `/proc/self/maps` 스캔으로 frida-agent 노출 탐지 |
| `_exit` 호출원 추적 | **`libAppIron +0xbd4c`** 종료 지점 특정 |
| Ghidra 정적분석 | `FUN_001096d0` — 파일 문자열 스캔 후 `_exit(0)` 구조 확인 |
| dumpsys | 경고창 = `XXXXNotifyPopupActivity`, 액션 `MCARE_ACTION_APP_KILL` |
| jadx 역추적 | `XXXXCommonActivity.onStart` → `RealizationOfJustice.isRooting()` |
| Find Usage | 구현체 `LocalRepositoryImpl`, 호출자 `InitializeAppLoadingUseCase` 특정 |

핵심 교훈: `_exit` 호출원 추적으로 네이티브 종료 지점을 특정하고, dumpsys와 jadx로 Java 레이어를 역추적해 **두 레이어를 분리 식별**한 것이 우회의 전제가 됨.

## 5. 최종 우회 (bypass-localrepo.js)

세 지점을 동시에 무력화함.

### (1) Java 루팅 체크 무력화
`RealizationOfJustice.isRooting()`을 후킹해 예외를 던지지 않고 정상 리턴시킴 → onStart의 popup+kill 경로 차단.
```javascript
var ROJ = Java.use("com.XXXX.mcare.new_framework.util.RealizationOfJustice");
ROJ.isRooting.overloads.forEach(function(ov){
    ov.implementation = function(){ return; };
});
```

### (2) 무결성 검증 결과 강제 성공
구현체 `LocalRepositoryImpl.startAppIron()`을 후킹해 항상 `AppIronResult.Success`를 리턴 → `InitializeAppLoadingUseCase`가 로딩을 정상 진행.
```javascript
var Success = Java.use("com.XXXX.mcare.domain.model.result.AppIronResult$Success");
var Impl = Java.use("com.XXXX.mcare.data.repository.LocalRepositoryImpl");
Impl.startAppIron.overloads.forEach(function(ov){
    ov.implementation = function(cont){
        return Success.INSTANCE;
    };
});
```

### (3) 네이티브 종료 차단 (안전장치)
libAppIron 로드 즉시 libc `_exit`/`exit`/`abort`를 무력화 → 네이티브 워치독 종료 방어.
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

## 6. 우회가 성공한 이유

| 레이어 | 탐지 방식 | 우회 지점 | 효과 |
|---|---|---|---|
| Java onStart | `isRooting()` 예외 | 메소드 → void 리턴 | popup/kill 제거 |
| 무결성 게이트 | `Error` 리턴 | `startAppIron` → Success | 무한로딩 해소 |
| 네이티브 워치독 | `_exit` 직접 호출 | libc exit replace | 강제종료 방어 |

핵심은 **네이티브와 싸우지 않고 Java 레이어에서 끊은 것**임. AppIron 네이티브 탐지(maps/XOM/ptrace)는 런타임 후킹으로 앞지르기 어려웠으나, 최종 판정 결과가 Kotlin 래퍼(`LocalRepositoryImpl.startAppIron`)를 거쳐 Java로 올라오므로, 그 지점에서 `Success`를 반환시켜 **네이티브 탐지 자체는 돌되 결과만 무력화**함. 네이티브 `_exit` 차단은 보조 안전장치로 작동함.

## 7. 다음 단계 (트래픽 캡처)
앱이 정상 실행되므로 루팅폰의 시스템 CA를 통해 Burp 프록시로 HTTPS 캡처 가능함. SSL 피닝 여부는 실제 트래픽에서 확인 필요함.

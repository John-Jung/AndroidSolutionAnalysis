# 상용 RASP(AppSealing 계열) 탐지 메커니즘 분석

> 본 문서는 특정 벤더/앱 식별 정보를 마스킹한 기술 분석 자료임. 대상 앱·기업명은 `[TARGET_APP]` / `[VENDOR]` 등으로 대체함.

## 1. 대상 정보

| 항목 | 내용 |
|---|---|
| 앱 | `[TARGET_APP]` (`[PACKAGE_NAME]`) |
| 기기 | `[DEVICE]`, Android 10, arm64, Magisk 루팅 |
| 분석 목적 | 트래픽 캡처 → 서버 API 취약점 발굴 (버그바운티) |
| 보호 솔루션 | 상용 RASP (AppSealing 계열, `[VENDOR]`) |
| 탐지 본체 | `libdxbase.so` (arm64 split APK, 약 515KB) |

## 2. 보호 솔루션 식별 과정

- Java 전역 문자열 암호화 `[VENDOR_PKG].dc.mXXXX()` 확인 → 상용 RASP 시그니처
- `.so` 목록에서 탐지 본체 후보 식별: TEE 모듈(무관), **탐지 본체 `libdxbase.so`**, 암호화 헬퍼
- import 함수로 확정: `pthread_create`(워치독), `open/read/openat/opendir/readdir`(proc·maps 스캔), `access`(루팅파일), `syscall`(libc 우회), `abort/exit/kill`
- 노이즈 제외: 크래시 리포팅 SDK의 `isRooted`(디바이스 메타 수집, 차단 아님)

## 3. 정적 분석의 벽

| 시도 | 결과 |
|---|---|
| 문자열 역추적 | 문자열 암호화 (평문 탐지 문자열 0, `FUN_00124124`로 런타임 복호화) |
| thunk XREF 역추적 | GOT 간접호출로 호출자 추적 불가 |
| Ghidra 이미지베이스 | 0x100000 (런타임 오프셋 + 0x100000 = Ghidra 주소) |

## 4. 동적 선점 분석 기법 (핵심 돌파구)

정적이 막혀 **frida 로드 선점**으로 탐지 스레드 주소를 런타임에 획득:

1. `android_dlopen_ext` / `__loader_android_dlopen_ext` 후킹 → 탐지 .so 로드 순간 포착
2. 로드 시점에 `JNI_OnLoad`(base+0x1bc20), import PLT slot 획득
3. `libc!pthread_create`를 전역 attach, **호출자 return address가 탐지 .so 범위인 것만 필터** → 탐지 스레드 시작 함수 주소 전부 추출

**주의:** GOT slot 직접 덮어쓰기(`writePointer`)는 frida-agent 크래시 유발 → `Interceptor.attach` + args 수정 방식만 안전. 종료 함수 slot을 더미 치환하면 cross-check(후술)에 걸려 역효과.

## 5. 탐지 스레드 전체 지도

| start_routine (base+) | Ghidra 주소 | 역할 | 종료 호출 |
|---|---|---|---|
| +0x37ab4 | 0x137ab4 | 파일 존재 7종 검사 (fopen/open/stat/lstat/access/glob) — 루팅 파일 | X (결과 리턴) |
| +0x3fcd0 | 0x13fcd0 | 디렉토리 CRC32 블랙리스트 — 루팅 앱 탐지 | X |
| +0x59a8c | 0x159a8c | 암호화 경로 파일 파싱 (키 검색, maps 의심) | X |
| +0x5a020 | 0x15a020 | 파일 읽고 `:` 앞 필드 추출 | X |
| +0x413ac | 0x1413ac | **워치독 — self-check + CallSupervisor 종료** | **O (svc)** |
| +0x414bc/d0 | 0x1414d0 | **frida 타이밍 anti-debug 본체** | (핸들러 경유) |
| 판정부 +0x2a924 | 0x12a924 | 앱 경로/패키지명 무결성 검증 | X |

각 탐지 함수는 "탐지 수행 + 결과를 param 구조체에 기록"만 하고, 종료는 워치독/핸들러에서 수행.

## 6. anti-frida 핵심 메커니즘

### (1) 타이밍 측정
```
uVar2 = cntvct_el0;        // ARM 사이클 카운터
CallSupervisor(0);          // svc 직접 (maps open/read, libc 우회)
uVar3 = cntvct_el0;
if (0x465000 < uVar3-uVar2) // 460만 사이클 초과 = 후킹으로 느려짐 = 탐지
    (DAT_00187aa0 ^ 0xbe8acff5)(...);  // 대응 핸들러 호출
```
frida 후킹 오버헤드로 svc 실행이 느려지면 탐지. **frida 존재 자체를 타이밍으로 감지.**

### (2) 확률적 종료 핸들러 (FUN_0011e6e8 = DAT_00187aa0 ^ 0xbe8acff5)
```
uVar1 = (스택주소 ^ cntvct_el0) ^ 0x11e6f8;
uVar1 = xorshift(uVar1) & 3;    // 0~3 유사난수
if (uVar1==3) return;           // 1/4 통과
if (uVar1==1) return;           // 1/4 통과
if (uVar1==2) return;           // 1/4 통과
CallSupervisor(0); do{CallSupervisor(0);}while(1);  // 1/4만 종료
```
탐지돼도 **4분의 1 확률로만 종료** → 재현성 파괴로 리버서 교란. "같은 조건인데 어떤 땐 살고 어떤 땐 죽는" 불규칙성의 원인.

### (3) 함수포인터 난독화
탐지 대응 핸들러 주소(0x11e6e8)를 `^ 0xbe8acff5` XOR 인코딩해 `DAT_00187aa0`에 저장(`_INIT_2` 0x11e0d0에서 세팅). 런타임에 다시 XOR로 복원.

### (4) self-check 워치독 (FUN_001413ac)
```
local_48 = DAT_00187c18 ^ 0x40000;        // 기대값 미리 계산
pthread_create(FUN_001414bc);              // 실제 탐지 스레드
pthread_join;                              // 완료 대기
if (local_44==0 || local_48 != DAT_00187c18)  // 탐지 스레드가 제대로 안 돌았으면
    CallSupervisor(0); do{...}while(1);    // svc 종료
```
탐지 스레드가 `DAT_00187c18`을 예상대로 변경했는지 **역검증**. 탐지 스레드를 더미 치환하면 이 값이 안 바뀌어 종료 → **단순 스레드킬이 실패한 이유.** 추가로 `DAT_00187a64 < 3` 조건으로 **최대 3회 자가재생**(죽여도 되살아남).

### (5) svc 직접 종료
종료를 전부 `CallSupervisor`(인라인 svc #0)로 수행 → libc `exit`/`kill`/`syscall` wrapper 후킹이 전부 무효.

## 7. frida 런타임 우회 불가 결론

구조적으로 frida로는 우회 불가:
1. **타이밍 기반** — frida 후킹 오버헤드로 반드시 `0x465000` 초과 → 탐지
2. **확률적 종료** — "통과"해도 다음 실행에 죽음 → 안정적 우회 불가
3. **svc 직접** — libc 후킹 전부 무효
4. **self-check + 자가재생** — 스레드 죽여도 되살아나고, 안 죽인 척도 self-check에 걸림

## 8. 우회 경로 분석

### 현실적 유일 경로 = 정적 패칭
- 탐지 .so의 타이밍 비교 분기(`0x465000` cmp) 전부 nop
- FUN_001413ac self-check 종료 분기 nop
- FUN_0011e6e8 확률종료 분기 nop
- **self-CRC(자기 무결성 검사) 확인 필요** ← 미완
- APK 재압축 + 재서명

### 대안 (cntvct_el0 조작) — 사실상 불가
- Stalker 명령 재작성: 메모리 변조라 메모리 self-CRC 위험 + Stalker 오버헤드가 타이밍 체크 자폭
- 타이머 값 조작: `mrs cntvct_el0`는 EL0 레지스터 직접 읽기라 커널 권한(CNTKCTL_EL1 트랩) 필요 → frida만으론 불가

### 서버검증 리스크 (미확인)
- 고보안 앱이라 **서버 Play Integrity / APK 해시 검증** 가능성 높음
- 클라이언트 self-CRC/self-signature는 패칭으로 우회 가능하나, 서버검증은 로컬 패칭 무의미
- Shamiko 루팅 은신은 **실패** (RASP 루팅 탐지가 Zygisk 레벨로 안 숨겨짐)

## 9. self-CRC 분석 현황 (진행 중)

- CRC32 테이블: `DAT_0010b1a4` (표준 CRC32, `0x10b1a8`부터 `0x77073096...`)
- 테이블 참조 84개가 `FUN_0011a370` 한 함수에 집중 (언롤링된 CRC 계산 루프)
- `FUN_0011a370`은 CRC+포맷팅+부동소수점 혼합 거대 복합 함수
- 기대 CRC값 대조 지점: `DAT_00185328 == uVar22`
- **미확인:** 이 CRC가 self-CRC인지(자기 .so/.apk 바이트 대상) vs 앱 블랙리스트 CRC인지 → `DAT_00185328` XREF 역추적 필요

## 10. 다음 단계 (택1)

1. **self-CRC 확인 지속** — `0x185328` XREF로 CRC 검증 대상 확정
2. **서버검증 먼저 확인** — 정상폰에서 로그인/API 트래픽 캡처, Play Integrity 토큰 전송 유무 확인 (패칭 결실 여부 사전 판단)
3. **분석 일단락** — 현 분석을 RASP 자산으로 확정, 패칭은 별도 진행

**권고:** 2번(서버검증 선확인) — 정적 패칭 완료 후 서버벽에 막히면 헛수고이므로, 서버 무결성 검증 유무를 먼저 판가름하는 것이 효율적.

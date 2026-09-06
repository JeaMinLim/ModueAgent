# AGENTS_KO.md — AI 코딩 어시스턴트를 위한 마스터 가이드라인

**ModueAgent**에 오신 것을 환영합니다. 이 문서는 이 저장소와 상호작용하는 AI 코딩 에이전트와 개발자를 위한 **단일 진실 공급원(SSOT)**입니다.

모든 AI 어시스턴트(Claude Code, Cursor, GitHub Copilot, Google Gemini, Antigravity, Cortex 등)는 아래에 명시된 규칙, 보안 불변식, 코딩 표준을 엄격히 준수해야 합니다.

---

## 1. 프로젝트 철학 및 핵심 불변식

ModueAgent는 [ModueHarness 마이크로커널 보안 원칙](docs/MODUEHARNESS_PRINCIPLES_KO.md)의 마이크로커널 보안 원칙에서 파생된 **Zero-Trust AI 에이전트 프레임워크**입니다.

### 근본적 불변식
> **"LLM은 본질적으로 신뢰할 수 없다."**  
> LLM은 외부 비신뢰 데이터로부터의 간접 프롬프트 주입(Indirect Prompt Injection)을 통해 언제든 인지 납치될 수 있습니다. 따라서 프레임워크는 자연어 프롬프트에 보안을 의존해서는 안 되며, 역량(Capability), 샌드박싱, 커널 경계를 통해 구조적으로 보안을 강제해야 합니다.

### 5대 핵심 보안 규칙
1. **물리적 & 논리적 분리**: 추론(유저 공간의 인지)과 실행(샌드박스 도구 관리자)의 엄격한 분리.
2. **객체 역량 (Zero-Trust)**:
   - 만능 전역 권한 금지.
   - 단기 TTL을 가진 JIT(Just-In-Time) 일회성 토큰 사용.
   - 권한 감쇠 규칙: 위임된 토큰은 부모 권한이나 부모 만료 시간을 초과할 수 없음.
   - 연쇄 회수: 부모 토큰 취소 시 모든 파생 자식 토큰 자동 무효화.
   - 와일드카드 금지 (`tool:*` 엄격 차단).
3. **자원 부작용 등급 (`EffectClass`)**:
   - `READ`: 안전, 조회 전용, 캐싱 허용, TTL <= 3600초.
   - `WRITE`: 가역적 상태 변경, 캐싱 불가, TTL <= 600초.
   - `DESTRUCTIVE`: 비가역적 파괴(삭제, 드롭, 이체 등), TTL <= 60초, **사전 검증 트랩 / HITL 확인 필수**.
4. **XOA (Execute-Only Architecture) 출력 샌드박싱**:
   - 도구 출력은 `extract_safe`를 통해 `extract_paths`에 사전 선언된 필드만 추출.
   - 원시 출력(`raw_output`)은 즉시 메모리에서 폐기하여 시크릿, 경로, 환경변수 유출 차단.
5. **과금 테러(Denial of Wallet) 방어**:
   - 실행 스텝 상한(`max_steps`) 및 토큰 한도(`max_tokens`) 강제.
   - 한도 도달 시 즉시 중단하고 검증된 히스토리로부터 안전한 부분 요약 답변 도출.

---

## 2. 언어 및 문서화 정책

- **기본 언어**: 영어는 코드, 독스트링, 변수명, 단위 테스트, 커밋 메시지, 메인 문서(`README.md`, `CHANGELOG.md`)의 기본 언어입니다.
- **보조 언어**: 한국어는 사용자 안내 문서(`README_KO.md`, `DEVELOPER_GUIDE_KO.md`)로 병행 유지됩니다.

---

## 3. 기술 스택 및 의존성

- **언어**: Python 3.10+
- **무의존성(Zero-Dependency) 철학**: 코어 프레임워크(`src/modueagent/`)는 **오직 Python 표준 라이브러리**만 사용합니다.
- **테스트**: Python 내장 `unittest` (`pytest` 호환).

---

## 4. 코딩 표준 및 컨벤션

1. **타입 힌트**: 철저한 타입 어노테이션 사용 (`from __future__ import annotations`, `typing.Optional`, `Union`, `Dict`, `List`, `Any`).
2. **데이터 모델**: 보안 토큰과 불변 메시지에는 `@dataclass(frozen=True)` 우선 사용.
3. **Fail-Closed 원칙**: 검증 오류나 권한 불일치 시 기본적으로 거부(Fail-Closed) 처리.
4. **에러 마스킹**: 내부 시스템 스택트레이스나 절대경로를 LLM 또는 사용자에게 직접 노출하지 않고 정규화.
5. **위험한 내장 함수 금지**: `eval()`, `exec()`, `os.system()`, `pickle` 사용 절대 금지 (`safe_eval_arithmetic()` 사용).

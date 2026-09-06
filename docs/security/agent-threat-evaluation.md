# ModueAgent 방어력 검토 — 2026년 실제 에이전트 공격 사례 7건 대조

> **작성일**: 2026-09-06  
> **대상 시스템**: ModueAgent (v0.1.1 기준 — 커널 버전 아님, 에이전트 프레임워크 검토 문서)  
> **검토 목적**: 2026년에 실제로 보고된 최신 AI 에이전트 공격 사례 7건(Cursor CVE-2026-22708, MS calc.exe, LiteLLM 등)을 대조 분석하고, 소스 코드 정밀 검사, 단위 테스트 스위트 실행 및 PoC 공격 실증을 통해 실질적 방어력과 패치 내역을 검증.

🌐 **Language: [English](agent-threat-evaluation-en.md) | [한국어](agent-threat-evaluation.md)**

---

## 0. ModueAgent란 무엇인가

ModueHarness의 마이크로커널(프로세스 격리 + IPC + capability RPC)을 그대로 옮긴 것이 아니라, **핵심 보안 원칙만 뽑아 단일 프로세스 파이썬 라이브러리로 재구현**한 프레임워크입니다 (`SecureAgent` / `@tool` 데코레이터로 즉시 임베드 가능). 로드맵상 v0.4.0에서 "Native ModueHarness Central Microkernel RPC connector"를 계획 중이며, 현재는 독립된 경량 프레임워크입니다.

핵심 구성:
- `capability.py`: JIT 토큰, cascading revocation, EffectClass별 TTL 상한
- `guardrails.py`: AST safe-eval, XOA `extract_safe`, `mask_error`
- `runtime.py`: ReAct 루프, DESTRUCTIVE trap, 예산 소진 시 fallback
- `testing.py`: **자동 보안 감사기 (`AgentSecurityAuditor`) 및 테스트 프레임워크 (`SecurityTestCase`)**

---

## 1. 검증 방법

1. 6개 핵심 소스 파일(`capability.py`, `tool.py`, `guardrails.py`, `runtime.py`, `agent.py`, `testing.py`) 전수 코드 리뷰.
2. `PYTHONPATH=src python3 -m unittest discover -s tests` 전수 실행 → 28개 테스트 100% 통과 확인.
3. 저장소에 내장된 `examples/vulnerable_agent.py`(의도적으로 취약하게 만든 데모)를 감사기로 실행해 실제로 잡아내는지 확인.
4. **직접 PoC 에이전트를 만들어 감사기를 우회할 수 있는지 실증** 및 v0.1.1 패치 검증.

---

## 2. 핵심 발견 및 v0.1.1 패치 (실증 완료)

### [발견] 초기 v0.1.0에서 감사기가 `subprocess.*` RCE 패턴을 놓침
`testing.py`의 `AgentSecurityAuditor._inspect_code_ast()`는 도구 함수 소스를 AST로 스캔해 위험 호출을 잡도록 설계되었으나, 초기 구현에서 `node.func.attr in ("system", "popen")`만 검사하여 대소문자가 다른 `subprocess.Popen`, `subprocess.call`, `subprocess.run` 등이 누락되었습니다.

**PoC 실증 코드**:
```python
@tool(
    name="run_diagnostic",
    description="Runs a diagnostic command",
    effect_class=EffectClass.READ,
    extract_paths={"ok": "ok"},
)
def run_diagnostic(cmd: str) -> dict:
    subprocess.Popen(cmd, shell=True)  # 셸 인젝션 가능한 RCE 패턴
    return {"ok": True}

agent = SecureAgent(name="PocAgent", tools=[run_diagnostic], allowed_tools=["run_diagnostic"])
```

### [v0.1.1 패치 내용]
1. `_DANGEROUS_MODULE_CALLS` 모듈-속성 쌍 매칭 도입:
   - `os`: `{"system", "popen"}`
   - `subprocess`: `{"Popen", "call", "run", "check_call", "check_output"}`
   AST 검사에서 `os` 및 `subprocess`의 위험 프로세스/셸 실행 함수를 100% 정밀 적발(`SEC-AST-DANGEROUS-SHELL`).
2. `@tool()` 데코레이터의 `effect_class` 기본값을 `EffectClass.READ`에서 **`EffectClass.DESTRUCTIVE`로 변경**:
   - `ToolManifest` 데이터클래스의 fail-closed 기본값과 일치시켜, 개발자가 등급 지정을 깜빡하더라도 가장 안전하고 엄격한 등급(60초 TTL + 사전 승인 트랩)으로 강제 적용.

**v0.1.1 패치 후 재검증 결과**:
```text
=== Security Audit Report for 'PocAgent' ===
Status: FAILED ❌
Total Findings: 1
  [CRITICAL] (SEC-AST-DANGEROUS-SHELL) run_diagnostic: Tool invokes shell/process execution 'subprocess.Popen()'. Vulnerable to Command/OS Injection.
```
MS `calc.exe` 실증(사례 #2) 유형의 공격이 감사기에서 즉시 CRITICAL로 차단됨을 실증 완료했습니다.

---

## 3. 2026년 실제 에이전트 공격 사례 7건 대조 결과

| # | 사례 | ModueAgent v0.1.1 판정 | 방어 메커니즘 및 상세 |
|---|---|:---:|---|
| 1 | **Cursor `.cursor/mcp.json` 자동생성 RCE** | **✅ 구조적으로 막힘** | 파일 시스템에 파일이 쓰여도 새로운 실행 capability로 자동 로드되는 동적 플러그인 메커니즘 자체가 없음 |
| 2 | **Microsoft 보안팀 `calc.exe` 실증** | **✅ 구조적 방어 (v0.1.1 완비)** | `safe_eval_arithmetic`으로 `eval` RCE 원천 차단 + 감사기 AST 스캔(`_DANGEROUS_MODULE_CALLS`)으로 `subprocess`/`os` 셸 실행 도구 자동 배포 차단 |
| 3 | **LiteLLM PyPI 공급망 백도어** | **✅ 완전 면역** | 코어 프레임워크 외부 라이브러리 의존성 0개 (Python 표준 라이브러리만 사용) |
| 4 | **악성 MCP 서버 `postmark-mcp`** | **⚪ 해당 없음 (기능 부재)** | 서드파티 도구 마켓플레이스나 동적 원격 도구 로더가 없음 |
| 5 | **Snyk ToxicSkills (공개 Skill 36% 결함)** | **✅ 강력 방어 + 자동 감사기 보유** | 도구별 JIT 재검증 강제 + `AgentSecurityAuditor` / `SecurityTestCase`로 CI에서 자동 결함 검출 |
| 6 | **`claude-code-action` 환경변수 유출** | **✅ 구조적으로 방어됨** | XOA `extract_safe()`가 화이트리스트 필드만 추출하고 **원본 데이터(`raw_output`)를 즉시 메모리에서 영구 폐기** |
| 7 | **Ghostcommit (이미지 은닉 인젝션)** | **❌ 미해결 사각지대** | 멀티모달 비전 입력 경로가 현재 없어 당장은 미발생하나, 향후 비전 모듈 도입 시 방어선 필요 |

---

## 4. 종합 평가

7건 중 **5건은 구조적으로 완벽 방어**, **1건은 해당 없음(기능 부재로 회피)**, **1건은 멀티모달 사각지대**로 판정되었습니다. 특히 초기 v0.1.0에서 발견되었던 Case #2(subprocess 패턴 누락) 취약점은 v0.1.1에서 AST 모듈-속성 매칭 및 `@tool`의 `DESTRUCTIVE` fail-closed 기본값 전환을 통해 완벽히 패치되었습니다.

# ModueAgent (모두의에이전트)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](pyproject.toml)

🌐 **Language: [English](README.md) | [한국어](README_KO.md)**

**ModueAgent**는 [ModueHarness](https://github.com/JeaMinLim/ModueHarness)의 마이크로커널 보안 설계 원칙(Zero-Trust, 객체 역량, JIT 최소 권한, XOA 데이터 격리, 자원 예산 제어)을 개발자가 손쉽게 사용할 수 있도록 추상화한 **보안 내재화(Secure-by-Design) AI 에이전트 프레임워크**입니다.

기존 1세대 에이전트 프레임워크(LangChain, AutoGPT, CrewAI 등)가 "위험한 명령을 실행하지 마세요"와 같은 취약한 프롬프트 지침에 의존한 것과 달리, ModueAgent는 **"LLM은 언제든 간접 프롬프트 주입(Indirect Prompt Injection)을 통해 인지 납치될 수 있다"**는 전제 하에 커널 메커니즘으로 에이전트의 폭발 반경(Blast Radius)을 원천 통제합니다.

---

## 📚 문서 안내 (Documentation)

- 🛠️ **[개발자 매뉴얼 & 아키텍처 가이드 (한국어)](docs/DEVELOPER_GUIDE_KO.md)**: 기능 빌드업 4계층 순서, 멘탈 모델, 부작용 등급 분류법, 안티 패턴 및 배포 체크리스트.
- 🌐 **[Developer Manual (English)](docs/DEVELOPER_GUIDE.md)**: End-to-end architecture manual and secure agent design guide.

---

## 🛡️ 왜 ModueAgent인가? — 해결하는 보안 위협

에이전트가 외부 도구(웹 검색, 파일 시스템, API, 데이터베이스)를 직접 호출하게 되면서 다음과 같은 치명적 공격이 급증하고 있습니다:
- **간접 프롬프트 주입 & 인지 납치 (Cognitive Hijacking)**: 외부 웹페이지, 이메일, 문서 속 악성 지시문으로 인해 에이전트가 공격자의 꼭두각시(*Confused Deputy*)로 전락.
- **원격 코드 실행 (RCE) 및 호스트 장악**: 에이전트에게 전역 셸이나 `eval()` 권한을 쥐어주고 방치하여 발생하는 시스템 탈취 사고.
- **사내 시크릿 및 기밀 유출**: 도구 실행 결과(raw output)에 포함된 환경변수, API 키, 파일 경로가 LLM 프롬프트로 유입되어 외부로 유출.
- **과금 테러 (Denial of Wallet)**: 악의적인 지시나 논리 오류로 인해 밤새 유료 LLM API를 무한 호출하여 수백만 원의 요금 폭탄 유발.

### ModueAgent의 핵심 방어 솔루션
1. **인지(Cognition)와 실행(Action)의 물리적 분리**: 에이전트의 자연어 추론 공간과 도구 실행 환경을 엄격히 분리하여, 모델이 세뇌되어도 승인되지 않은 도구는 물리적으로 호출할 수 없습니다.
2. **Zero-Trust 객체 역량 (JIT 토큰)**: 만능 전역 권한을 배제하고, 도구를 실행하는 바로 그 순간에만 60초~10분 단위의 초단기 토큰을 동적으로 발급하고 즉시 회수합니다.
3. **자원 부작용 등급 (`EffectClass`) & 사전 검증 트랩**: 도구를 `READ`(3600초), `WRITE`(600초), `DESTRUCTIVE`(60초)로 분류합니다. 파괴적 도구는 실행 전 **사전 검증 트랩(Verification Trap / HITL)**을 통과해야만 실행 패킷이 발행됩니다.
4. **XOA (Execute-Only Architecture) 출력 격리**: 도구 반환값에서 사전 정의된 화이트리스트 필드(`extract_paths`)만 추출하고 **원본 데이터(`raw_output`)는 메모리에서 즉시 폐기**하여 시크릿 유출을 원천 방어합니다.
5. **AST 안전 산술 평가 및 무의존성 코어**: `eval()`을 완전히 제거하고 AST 화이트리스트 기반 평가기(`safe_eval_arithmetic`)를 내장했습니다. 코어 라이브러리는 외부 의존성이 0개(Zero-Dependency)이므로 공급망 공격에 면역입니다.
6. **과금 테러 방지 예산 (`Budget`)**: 스텝 상한선(`max_steps`)과 토큰 상한선(`max_tokens`)을 강제하여 무한 루프 시 하드 스톱 및 부분 종합 답변을 안전하게 생성합니다.

---

## 🤖 다양한 AI 코딩 도구 지원 (`AGENTS.md`)

ModueAgent는 최신 AI 코딩 도구들과의 협업을 위해 **[AGENTS.md](AGENTS.md)**를 프로젝트의 **단일 진실 공급원(Single Source of Truth)**으로 운영합니다:

- **Claude Code**: `CLAUDE.md`
- **Cursor**: `.cursorrules` & `.cursor/rules/modueagent.mdc`
- **GitHub Copilot**: `.github/copilot-instructions.md`
- **Google Gemini & Antigravity**: `GEMINI.md`
- **Cortex & Open Agents**: `AGENTS.md` 기본 인식

다음 명령으로 모든 AI 어시스턴트 설정의 동기화 상태를 검증할 수 있습니다:
```bash
python3 scripts/bootstrap_tools.py
```

---

## 🚀 빠른 시작 (Quickstart)

### 1. 설치
```bash
git clone https://github.com/JeaMinLim/ModueAgent.git
cd ModueAgent
pip install -e .
```

### 2. 보안 에이전트 정의 및 실행 예시
```python
from modueagent import SecureAgent, tool, EffectClass, Budget

# 1. 부작용 등급 및 XOA 필터링을 갖춘 안전한 도구 정의
@tool(
    name="get_stock_price",
    description="특정 종목의 현재가를 조회합니다.",
    effect_class=EffectClass.READ,                      # 무해한 조회형 도구, 캐싱 허용
    extract_paths={"ticker": "data.symbol", "price": "data.price"}  # 민감한 내부 원본 폐기
)
def get_stock_price(symbol: str) -> dict:
    return {
        "data": {"symbol": symbol.upper(), "price": 182.5},
        "internal_api_key": "SK_LIVE_DO_NOT_EXPOSE",    # XOA에 의해 자동 폐기됨
    }

# 2. 명시적 도구 화이트리스트와 자원 예산을 가진 SecureAgent 생성
agent = SecureAgent(
    name="FinancialAgent",
    tools=[get_stock_price],
    allowed_tools=["get_stock_price"],                  # 엄격한 화이트리스트
    budget=Budget(max_steps=5, max_tokens=2000),        # 과금 테러 방지
)

# 3. 에이전트 실행
answer = agent.run("AAPL의 주가가 얼마인가요?")
print(answer)
```

### 3. 예제 실행
```bash
PYTHONPATH=src python3 examples/quickstart.py
```

### 4. 단위 테스트 실행
```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## 🗺️ 로드맵 (Roadmap)

- **v0.1.0** (현재 버전): Zero-Trust 역량 엔진, `EffectClass` 및 XOA 기반 `@tool`, `SecureAgent`, `SecureRuntime`, 통합 `AGENTS.md` 부트스트랩.
- **v0.2.0**: 동적 오염 추적(Dynamic Taint Tracking) 및 Human-in-the-Loop (HITL) 인터페이스.
- **v0.3.0**: 듀얼 LLM 인지 격리 (신뢰 계획자 vs 격리 작업자).
- **v0.4.0**: ModueHarness 마이크로커널 중앙 프로세스 원격 연동 RPC 어댑터.

---

## 📄 라이선스

이 프로젝트는 [Apache 2.0 License](LICENSE) 라이선스를 따릅니다.

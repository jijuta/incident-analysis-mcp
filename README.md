# 인시던트 분석 MCP 서버

OpenSearch 인시던트 데이터를 분석하여 표, 차트, 보고서를 생성하는 Model Context Protocol (MCP) 서버입니다.

## 🚀 기능

### 📊 인시던트 통계 분석
- 심각도별 인시던트 분포 테이블
- 일별/시간별 인시던트 발생 현황
- 전체 요약 통계

### 📈 트렌드 차트 생성
- 시간별/일별 인시던트 발생 트렌드
- 선형 차트로 시각화
- PNG 이미지 형태로 출력

### 🎯 위협 유형 분석
- 상위 위협 유형 순위 테이블
- 파이 차트로 분포 시각화
- 비율 및 발생 건수 제공

### 🌍 지리적 분포 분석
- 국가별 인시던트 발생 현황
- 막대 차트로 상위 10개국 시각화
- 지역별 보안 위험도 파악

### 📋 종합 보고서 생성
- 모든 분석 결과를 통합한 마크다운 보고서
- 권장사항 및 다음 단계 제시
- 자동 생성된 종합 분석 문서

## 🔧 사용 가능한 도구

1. **get_incident_statistics**: 인시던트 통계 테이블 생성
2. **create_incident_trend_chart**: 트렌드 차트 생성
3. **analyze_top_threats**: 상위 위협 유형 분석
4. **analyze_geographic_distribution**: 지리적 분포 분석
5. **generate_incident_report**: 종합 보고서 생성

## 🚀 Quick Install

```bash
npm install -g git+https://github.com/jijuta/incident-analysis-mcp.git
```

## 📦 상세 설치 및 설정

### 1. 로컬 개발용 설치
```bash
cd /opt/docs/apps/opensearch/incident-analysis-mcp
npm install
```

### 2. 글로벌 설치 (권장)
```bash
npm install -g git+https://github.com/jijuta/incident-analysis-mcp.git
```

### 3. 환경 변수 설정
MCP 서버 URL은 환경 변수로 설정됩니다:
```bash
export MCP_SERVER_URL="http://your-server:your-port"
```
**OpenSearch 인증 정보는 백엔드 MCP 서버에서 안전하게 관리됩니다.**

## 🔗 Claude Desktop 연결

### 글로벌 설치 후 (권장)
Claude Desktop 설정 파일에 다음과 같이 추가:

```json
{
  "mcpServers": {
    "incident-analysis": {
      "command": "incident-analysis-mcp",
      "env": {
        "MCP_SERVER_URL": "http://20.41.120.173:8099"
      }
    }
  }
}
```

### 양쪽 도구 모두 사용하기 (권장)
OpenSearch 검색 + 인시던트 분석 기능을 모두 사용하려면:

```json
{
  "mcpServers": {
    "opensearch": {
      "command": "opensearch-mcp-inbridge",
      "env": {
        "MCP_SERVER_URL": "http://20.41.120.173:8099"
      }
    },
    "incident-analysis": {
      "command": "incident-analysis-mcp",
      "env": {
        "MCP_SERVER_URL": "http://20.41.120.173:8099"
      }
    }
  }
}
```

**💡 이렇게 설정하면 Claude Desktop에서 다음 모든 기능을 사용할 수 있습니다:**
- 📝 OpenSearch 인덱스 검색 및 조회
- 📊 인시던트 통계 분석
- 📈 트렌드 차트 생성
- 🎯 위협 유형 분석
- 🌍 지리적 분포 분석
- 📋 종합 보고서 생성

### 로컬 개발용
```json
{
  "mcpServers": {
    "incident-analysis": {
      "command": "node",
      "args": ["/opt/docs/apps/opensearch/incident-analysis-mcp/index.js"],
      "env": {
        "MCP_SERVER_URL": "http://20.41.120.173:8099"
      }
    }
  }
}
```

**⚠️ 중요: 정확한 MCP_SERVER_URL을 사용하세요 (포트 8099)**

## 🏗️ 아키텍처

이 MCP는 **보안상 안전한 프록시 방식**을 사용합니다:

```
Claude Desktop → incident-analysis-mcp → MCP Server → OpenSearch
```

- **No hardcoded servers**: 모든 서버 정보는 환경변수로만 설정
- **No credentials in code**: OpenSearch 인증 정보는 백엔드 MCP 서버에서 관리
- **Proxy pattern**: 직접 OpenSearch 연결 대신 중간 MCP 서버를 통한 안전한 접근

## 💬 Claude Desktop에서 사용하는 방법

### 📊 기본 통계 분석
```
"최근 7일간 인시던트 통계를 security-logs-* 인덱스에서 분석해줘"
"threat-intelligence-* 인덱스의 인시던트 통계를 테이블로 보여줘"
"지난 30일간 심각도별 인시던트 분포를 분석해줘"
```

### 📈 트렌드 분석 및 차트
```
"최근 7일간 인시던트 트렌드를 일별로 차트로 보여줘"
"시간별 인시던트 발생 패턴을 1시간 간격으로 분석해줘"
"최근 2주간 보안 이벤트 증감 추세를 그래프로 그려줘"
```

### 🎯 위협 유형 분석
```
"상위 10개 위협 유형을 분석해서 테이블과 파이차트로 보여줘"
"malware 관련 위협을 분석하고 분포도를 차트로 생성해줘"
"가장 빈번한 공격 유형 5개를 찾아서 시각화해줘"
```

### 🌍 지리적 분포 분석
```
"국가별 인시던트 분포를 분석해서 막대그래프로 보여줘"
"지역별 보안 위험도를 분석하고 상위 10개국을 차트로 표시해줘"
"아시아 지역의 인시던트 패턴을 분석해줘"
```

### 📋 종합 보고서 생성
```
"최근 7일간의 종합적인 보안 인시던트 분석 보고서를 작성해줘"
"월간 보안 동향 보고서를 생성해줘 (최근 30일 기준)"
"CEO용 보안 요약 보고서를 만들어줘"
```

### 🔍 고급 분석 요청
```
"특정 IP 대역(192.168.*)에서 발생한 인시던트를 분석해줘"
"critical 등급 인시던트의 시간대별 분포를 분석해줘"
"반복되는 공격 패턴을 찾아서 보고서로 정리해줘"
```

### ⚙️ 커스텀 분석 옵션
```
"log-security-* 인덱스에서 최근 14일간 데이터로 분석해줘"
"threat_category 필드를 기준으로 위협 분류를 해줘"
"source_country 필드로 지리적 분석을 수행해줘"
```

## 🏗️ 기술 스택

- **Node.js**: 런타임 환경
- **@modelcontextprotocol/sdk**: MCP 프로토콜 구현
- **axios**: HTTP 클라이언트 (MCP 서버 통신)
- **chart.js + canvas**: 차트 생성 (선택적 의존성)
- **d3**: 데이터 시각화 (선택적 의존성)
- **markdown-table**: 마크다운 테이블 생성
- **date-fns**: 날짜 처리
- **lodash**: 유틸리티 함수

### 📊 차트 지원

- **Linux/macOS**: 모든 차트 기능 지원 (테이블 + PNG 차트)
- **Windows**: 테이블 전용 모드 (Canvas 설치 문제로 차트 기능 제외)
- **자동 감지**: 시스템에 따라 차트 지원 여부를 자동으로 감지

## 📊 데이터 요구사항

### 필수 필드
- `@timestamp`: 인시던트 발생 시간
- `severity`: 심각도 (critical, high, medium, low)
- `threat_type`: 위협 유형
- `geoip.country_name`: 국가명 (지리적 분석용)

### 인덱스 패턴
- 기본값: `security-logs-*`
- 사용자 정의 인덱스 패턴 지원

## 🔍 문제 해결

### OpenSearch 연결 오류
```bash
# OpenSearch 서버 상태 확인
curl -k -u admin:Admin@123456 https://localhost:9200/_cluster/health

# 환경 변수 확인
echo $OPENSEARCH_URL
echo $OPENSEARCH_USERNAME
```

### 차트 생성 오류
- Canvas 의존성 확인: `npm list canvas`
- 이미지 생성 권한 확인

### 데이터 없음 오류
- 인덱스 패턴 확인
- 날짜 범위 조정
- 필드명 확인

## 📄 라이선스

MIT License

---

**🎯 목표**: OpenSearch 보안 데이터를 쉽게 분석하고 시각화하여 효과적인 보안 인시던트 대응을 지원합니다.
#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import { markdownTable } from 'markdown-table';
import { format, subDays, parseISO } from 'date-fns';
import _ from 'lodash';

// 차트 의존성을 선택적으로 로드
let createCanvas, Chart, d3;
let CHART_SUPPORT = false;

try {
  const canvasModule = await import('canvas');
  const chartModule = await import('chart.js/auto');
  const d3Module = await import('d3');

  createCanvas = canvasModule.createCanvas;
  Chart = chartModule.default;
  d3 = d3Module;
  CHART_SUPPORT = true;
  console.error('✅ Chart support enabled');
} catch (error) {
  console.error('⚠️ Chart dependencies not available, running in table-only mode');
  CHART_SUPPORT = false;
}

// MCP 서버 URL 설정 (환경변수로만 설정)
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

if (!MCP_SERVER_URL) {
  console.error('❌ MCP_SERVER_URL environment variable is required');
  console.error('');
  console.error('Please set the MCP server URL in your Claude Desktop configuration:');
  console.error('{');
  console.error('  "mcpServers": {');
  console.error('    "incident-analysis": {');
  console.error('      "command": "incident-analysis-mcp",');
  console.error('      "env": {');
  console.error('        "MCP_SERVER_URL": "http://your-server:your-port"');
  console.error('      }');
  console.error('    }');
  console.error('  }');
  console.error('}');
  console.error('');
  console.error('Contact your system administrator for the correct MCP_SERVER_URL value.');
  process.exit(1);
}

// OpenSearch 쿼리를 MCP 서버를 통해 실행하는 함수
async function executeOpenSearchQuery(query) {
  try {
    const response = await axios.post(`${MCP_SERVER_URL}/search`, query, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 60000,
    });
    return response.data;
  } catch (error) {
    throw new Error(`OpenSearch query failed: ${error.message}`);
  }
}

// MCP 서버 생성
const server = new Server(
  {
    name: 'incident-analysis-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// 인시던트 데이터 분석 도구들
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'get_incident_statistics',
        description: '인시던트 통계 데이터를 가져와서 마크다운 테이블로 생성합니다',
        inputSchema: {
          type: 'object',
          properties: {
            index_pattern: {
              type: 'string',
              description: '검색할 인덱스 패턴 (예: security-logs-*, incident-*)',
              default: 'security-logs-*',
            },
            days: {
              type: 'number',
              description: '분석할 일수 (기본값: 7일)',
              default: 7,
            },
            severity_field: {
              type: 'string',
              description: '심각도 필드명 (기본값: severity)',
              default: 'severity',
            },
          },
          required: ['index_pattern'],
        },
      },
      {
        name: 'create_incident_trend_chart',
        description: '인시던트 트렌드 차트를 생성합니다 (시간별, 일별)',
        inputSchema: {
          type: 'object',
          properties: {
            index_pattern: {
              type: 'string',
              description: '검색할 인덱스 패턴',
              default: 'security-logs-*',
            },
            days: {
              type: 'number',
              description: '분석할 일수',
              default: 7,
            },
            interval: {
              type: 'string',
              description: '시간 간격 (1h, 1d)',
              enum: ['1h', '1d'],
              default: '1d',
            },
          },
          required: ['index_pattern'],
        },
      },
      {
        name: 'analyze_top_threats',
        description: '상위 위협 유형을 분석하고 테이블과 차트로 생성합니다',
        inputSchema: {
          type: 'object',
          properties: {
            index_pattern: {
              type: 'string',
              description: '검색할 인덱스 패턴',
              default: 'security-logs-*',
            },
            days: {
              type: 'number',
              description: '분석할 일수',
              default: 7,
            },
            threat_field: {
              type: 'string',
              description: '위협 유형 필드명',
              default: 'threat_type',
            },
            top_count: {
              type: 'number',
              description: '상위 몇 개 위협을 분석할지',
              default: 10,
            },
          },
          required: ['index_pattern'],
        },
      },
      {
        name: 'generate_incident_report',
        description: '종합적인 인시던트 분석 보고서를 생성합니다',
        inputSchema: {
          type: 'object',
          properties: {
            index_pattern: {
              type: 'string',
              description: '검색할 인덱스 패턴',
              default: 'security-logs-*',
            },
            days: {
              type: 'number',
              description: '분석할 일수',
              default: 7,
            },
            report_title: {
              type: 'string',
              description: '보고서 제목',
              default: '보안 인시던트 분석 보고서',
            },
          },
          required: ['index_pattern'],
        },
      },
      {
        name: 'analyze_geographic_distribution',
        description: '지리적 분포 분석 및 시각화',
        inputSchema: {
          type: 'object',
          properties: {
            index_pattern: {
              type: 'string',
              description: '검색할 인덱스 패턴',
              default: 'security-logs-*',
            },
            days: {
              type: 'number',
              description: '분석할 일수',
              default: 7,
            },
            geo_field: {
              type: 'string',
              description: '지리 정보 필드명',
              default: 'geoip.country_name',
            },
          },
          required: ['index_pattern'],
        },
      },
    ],
  };
});

// 도구 실행 핸들러
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'get_incident_statistics':
        return await getIncidentStatistics(args);
      case 'create_incident_trend_chart':
        return await createIncidentTrendChart(args);
      case 'analyze_top_threats':
        return await analyzeTopThreats(args);
      case 'generate_incident_report':
        return await generateIncidentReport(args);
      case 'analyze_geographic_distribution':
        return await analyzeGeographicDistribution(args);
      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
  } catch (error) {
    throw new McpError(ErrorCode.InternalError, `Tool execution failed: ${error.message}`);
  }
});

// 인시던트 통계 테이블 생성
async function getIncidentStatistics(args) {
  const { index_pattern, days = 7, severity_field = 'severity' } = args;
  const endDate = new Date();
  const startDate = subDays(endDate, days);

  const query = {
    index: index_pattern,
    body: {
      query: {
        range: {
          '@timestamp': {
            gte: startDate.toISOString(),
            lte: endDate.toISOString(),
          },
        },
      },
      aggs: {
        severity_stats: {
          terms: {
            field: `${severity_field}.keyword`,
            size: 10,
          },
        },
        daily_count: {
          date_histogram: {
            field: '@timestamp',
            calendar_interval: '1d',
          },
        },
        total_incidents: {
          value_count: {
            field: '@timestamp',
          },
        },
      },
      size: 0,
    },
  };

  const response = await executeOpenSearchQuery(query);
  const aggs = response.body.aggregations;

  // 심각도별 통계 테이블
  const severityData = aggs.severity_stats.buckets.map(bucket => [
    bucket.key,
    bucket.doc_count.toString(),
    ((bucket.doc_count / aggs.total_incidents.value) * 100).toFixed(1) + '%',
  ]);

  const severityTable = markdownTable([
    ['심각도', '건수', '비율'],
    ...severityData,
  ]);

  // 일별 통계 테이블
  const dailyData = aggs.daily_count.buckets.map(bucket => [
    format(parseISO(bucket.key_as_string), 'yyyy-MM-dd'),
    bucket.doc_count.toString(),
  ]);

  const dailyTable = markdownTable([
    ['날짜', '인시던트 수'],
    ...dailyData,
  ]);

  const summary = `
# 인시던트 통계 분석 (최근 ${days}일)

## 전체 요약
- **총 인시던트 수**: ${aggs.total_incidents.value}건
- **일평균 인시던트**: ${Math.round(aggs.total_incidents.value / days)}건
- **분석 기간**: ${format(startDate, 'yyyy-MM-dd')} ~ ${format(endDate, 'yyyy-MM-dd')}

## 심각도별 분포
${severityTable}

## 일별 인시던트 발생 현황
${dailyTable}
  `;

  return {
    content: [
      {
        type: 'text',
        text: summary,
      },
    ],
  };
}

// 인시던트 트렌드 차트 생성
async function createIncidentTrendChart(args) {
  const { index_pattern, days = 7, interval = '1d' } = args;
  const endDate = new Date();
  const startDate = subDays(endDate, days);

  const query = {
    index: index_pattern,
    body: {
      query: {
        range: {
          '@timestamp': {
            gte: startDate.toISOString(),
            lte: endDate.toISOString(),
          },
        },
      },
      aggs: {
        trend: {
          date_histogram: {
            field: '@timestamp',
            calendar_interval: interval,
          },
        },
      },
      size: 0,
    },
  };

  const response = await executeOpenSearchQuery(query);
  const buckets = response.body.aggregations.trend.buckets;

  // 테이블 데이터 준비
  const tableData = buckets.map(bucket => [
    format(parseISO(bucket.key_as_string), interval === '1h' ? 'MM-dd HH:mm' : 'MM-dd'),
    bucket.doc_count.toString(),
  ]);

  const table = markdownTable([
    ['시간', '인시던트 수'],
    ...tableData,
  ]);

  const totalIncidents = buckets.reduce((sum, bucket) => sum + bucket.doc_count, 0);

  let content = [
    {
      type: 'text',
      text: `## 인시던트 트렌드 분석 (${interval} 간격)\n\n**총 ${totalIncidents}건의 인시던트가 발생했습니다.**\n\n${table}`,
    },
  ];

  // 차트 지원이 있으면 차트도 생성
  if (CHART_SUPPORT) {
    try {
      const labels = buckets.map(bucket =>
        format(parseISO(bucket.key_as_string), interval === '1h' ? 'MM-dd HH:mm' : 'MM-dd')
      );
      const data = buckets.map(bucket => bucket.doc_count);

      const width = 800;
      const height = 400;
      const canvas = createCanvas(width, height);
      const ctx = canvas.getContext('2d');

      const chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: '인시던트 수',
            data: data,
            borderColor: 'rgb(75, 192, 192)',
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            tension: 0.1,
          }],
        },
        options: {
          responsive: false,
          animation: false,
          plugins: {
            title: {
              display: true,
              text: `인시던트 트렌드 (최근 ${days}일)`,
            },
          },
          scales: {
            y: {
              beginAtZero: true,
            },
          },
        },
      });

      const buffer = canvas.toBuffer('image/png');
      const base64Image = buffer.toString('base64');

      content.push({
        type: 'image',
        data: base64Image,
        mimeType: 'image/png',
      });
    } catch (error) {
      console.error('Chart generation failed:', error.message);
    }
  }

  return { content };
}

// 상위 위협 분석
async function analyzeTopThreats(args) {
  const { index_pattern, days = 7, threat_field = 'threat_type', top_count = 10 } = args;
  const endDate = new Date();
  const startDate = subDays(endDate, days);

  const query = {
    index: index_pattern,
    body: {
      query: {
        range: {
          '@timestamp': {
            gte: startDate.toISOString(),
            lte: endDate.toISOString(),
          },
        },
      },
      aggs: {
        top_threats: {
          terms: {
            field: `${threat_field}.keyword`,
            size: top_count,
          },
        },
      },
      size: 0,
    },
  };

  const response = await executeOpenSearchQuery(query);
  const threats = response.body.aggregations.top_threats.buckets;

  // 테이블 데이터 생성
  const tableData = threats.map((threat, index) => [
    (index + 1).toString(),
    threat.key,
    threat.doc_count.toString(),
    ((threat.doc_count / response.body.hits.total.value) * 100).toFixed(1) + '%',
  ]);

  const table = markdownTable([
    ['순위', '위협 유형', '발생 건수', '비율'],
    ...tableData,
  ]);

  let content = [
    {
      type: 'text',
      text: `# 상위 위협 유형 분석 (최근 ${days}일)\n\n${table}`,
    },
  ];

  // 차트 지원이 있으면 파이 차트도 생성
  if (CHART_SUPPORT) {
    try {
      const canvas = createCanvas(600, 600);
      const ctx = canvas.getContext('2d');

      const chart = new Chart(ctx, {
        type: 'pie',
        data: {
          labels: threats.map(t => t.key),
          datasets: [{
            data: threats.map(t => t.doc_count),
            backgroundColor: threats.map((_, i) =>
              `hsl(${(i * 360) / threats.length}, 70%, 60%)`
            ),
          }],
        },
        options: {
          responsive: false,
          animation: false,
          plugins: {
            title: {
              display: true,
              text: `상위 ${top_count}개 위협 유형 분포`,
            },
            legend: {
              position: 'right',
            },
          },
        },
      });

      const buffer = canvas.toBuffer('image/png');
      const base64Image = buffer.toString('base64');

      content.push({
        type: 'image',
        data: base64Image,
        mimeType: 'image/png',
      });
    } catch (error) {
      console.error('Chart generation failed:', error.message);
    }
  }

  return { content };
}

// 지리적 분포 분석
async function analyzeGeographicDistribution(args) {
  const { index_pattern, days = 7, geo_field = 'geoip.country_name' } = args;
  const endDate = new Date();
  const startDate = subDays(endDate, days);

  const query = {
    index: index_pattern,
    body: {
      query: {
        range: {
          '@timestamp': {
            gte: startDate.toISOString(),
            lte: endDate.toISOString(),
          },
        },
      },
      aggs: {
        countries: {
          terms: {
            field: `${geo_field}.keyword`,
            size: 20,
          },
        },
      },
      size: 0,
    },
  };

  const response = await executeOpenSearchQuery(query);
  const countries = response.body.aggregations.countries.buckets;

  // 테이블 생성
  const tableData = countries.map((country, index) => [
    (index + 1).toString(),
    country.key,
    country.doc_count.toString(),
    ((country.doc_count / response.body.hits.total.value) * 100).toFixed(1) + '%',
  ]);

  const table = markdownTable([
    ['순위', '국가', '인시던트 수', '비율'],
    ...tableData,
  ]);

  let content = [
    {
      type: 'text',
      text: `# 지리적 분포 분석 (최근 ${days}일)\n\n${table}`,
    },
  ];

  // 차트 지원이 있으면 막대 차트도 생성
  if (CHART_SUPPORT) {
    try {
      const canvas = createCanvas(800, 500);
      const ctx = canvas.getContext('2d');

      const chart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: countries.slice(0, 10).map(c => c.key),
          datasets: [{
            label: '인시던트 수',
            data: countries.slice(0, 10).map(c => c.doc_count),
            backgroundColor: 'rgba(54, 162, 235, 0.8)',
            borderColor: 'rgba(54, 162, 235, 1)',
            borderWidth: 1,
          }],
        },
        options: {
          responsive: false,
          animation: false,
          plugins: {
            title: {
              display: true,
              text: '국가별 인시던트 분포 (상위 10개국)',
            },
          },
          scales: {
            y: {
              beginAtZero: true,
            },
          },
        },
      });

      const buffer = canvas.toBuffer('image/png');
      const base64Image = buffer.toString('base64');

      content.push({
        type: 'image',
        data: base64Image,
        mimeType: 'image/png',
      });
    } catch (error) {
      console.error('Chart generation failed:', error.message);
    }
  }

  return { content };
}

// 종합 보고서 생성
async function generateIncidentReport(args) {
  const { index_pattern, days = 7, report_title = '보안 인시던트 분석 보고서' } = args;

  // 각 분석 도구 실행
  const statistics = await getIncidentStatistics({ index_pattern, days });
  const topThreats = await analyzeTopThreats({ index_pattern, days });
  const geoDistribution = await analyzeGeographicDistribution({ index_pattern, days });

  const report = `
# ${report_title}

**생성일시**: ${format(new Date(), 'yyyy-MM-dd HH:mm:ss')}
**분석 기간**: 최근 ${days}일
**데이터 소스**: ${index_pattern}

---

${statistics.content[0].text}

---

${topThreats.content[0].text}

---

${geoDistribution.content[0].text}

---

## 권장사항

1. **높은 빈도의 위협 유형**에 대한 추가 보안 조치 검토
2. **지리적 이상 패턴** 감지 시 즉시 대응 체계 가동
3. **트렌드 변화** 모니터링을 통한 선제적 대응
4. **정기적인 보안 정책 점검** 및 업데이트

## 다음 단계

- [ ] 주요 위협 유형별 상세 분석
- [ ] 자동화된 대응 룰 설정
- [ ] 실시간 모니터링 대시보드 구성
- [ ] 정기 보고서 자동 생성 스케줄링

---

*본 보고서는 인시던트 분석 MCP를 통해 자동 생성되었습니다.*
  `;

  return {
    content: [
      {
        type: 'text',
        text: report,
      },
    ],
  };
}

// 서버 시작
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('✅ Incident Analysis MCP Server 시작됨');
}

main().catch((error) => {
  console.error('❌ 서버 시작 실패:', error);
  process.exit(1);
});
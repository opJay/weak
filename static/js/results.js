/**
 * Weak Scanner - Results Page JavaScript
 * 결과 페이지에서 스캔 상태 확인 및 결과 표시
 */

// Global variables
let currentScanId = null;
let statusPollInterval = null;
let currentResults = null;  // 전체 결과 저장
let currentSelection = null; // 현재 선택된 항목

// API Base URL
const API_BASE_URL = '/api';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializePage();
});

/**
 * Initialize page
 */
function initializePage() {
    // Get scan ID from data attribute
    const body = document.body;
    currentScanId = body.dataset.scanId;

    if (!currentScanId) {
        console.error('Scan ID not found!');
        showError('스캔 ID를 찾을 수 없습니다.');
        return;
    }


    // Initialize event listeners
    initializeEventListeners();

    // Start checking scan status
    checkScanStatus();
}

/**
 * Initialize event listeners
 */
function initializeEventListeners() {
    const shareBtn = document.getElementById('shareBtn');
    if (shareBtn) {
        shareBtn.addEventListener('click', shareScanResults);
    }

    // 키보드 네비게이션
    document.addEventListener('keydown', handleKeyboardNavigation);
}

/**
 * Check scan status
 */
async function checkScanStatus() {
    try {
        const response = await fetch(`${API_BASE_URL}/scan/${currentScanId}/status/`);

        if (!response.ok) {
            if (response.status === 404) {
                showError('스캔 결과를 찾을 수 없습니다.');
                return;
            }
            throw new Error('상태 확인 실패');
        }

        const data = await response.json();

        // Handle based on status
        switch (data.status) {
            case 'pending':
            case 'running':
                // Show loading section
                showLoading(data);
                // Start polling
                startStatusPolling();
                break;
            case 'completed':
                // Load and show results
                loadScanResults();
                break;
            case 'failed':
                // Show error
                showError(data.error_message || '스캔 중 오류가 발생했습니다.');
                break;
            default:
                showError('알 수 없는 상태입니다.');
        }
    } catch (error) {
        console.error('Status check error:', error);
        showError('상태 확인 중 오류가 발생했습니다.');
    }
}

/**
 * Start status polling
 */
function startStatusPolling() {
    // Clear any existing interval
    if (statusPollInterval) {
        clearInterval(statusPollInterval);
    }

    // Poll every 2 seconds
    statusPollInterval = setInterval(updateScanStatus, 2000);
}

/**
 * Update scan status
 */
async function updateScanStatus() {
    if (!currentScanId) return;

    try {
        const response = await fetch(`${API_BASE_URL}/scan/${currentScanId}/status/`);
        const data = await response.json();

        if (!response.ok) {
            throw new Error('상태 업데이트 실패');
        }

        // Update progress
        if (data.progress !== undefined) {
            updateProgress(data.progress);
        }

        // Check if completed
        if (data.status === 'completed') {
            clearInterval(statusPollInterval);
            statusPollInterval = null;
            loadScanResults();
        } else if (data.status === 'failed') {
            clearInterval(statusPollInterval);
            statusPollInterval = null;
            showError(data.error_message || '스캔 중 오류가 발생했습니다.');
        }

    } catch (error) {
        console.error('Status update error:', error);
        // Continue polling on error
    }
}

/**
 * Update progress display
 */
function updateProgress(progress) {
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');

    if (progressFill) {
        progressFill.style.width = `${progress}%`;
    }
    if (progressText) {
        progressText.textContent = `${progress}%`;
    }

    // Update step display based on progress
    const stepIcon = document.getElementById('stepIcon');
    const stepTitle = document.getElementById('stepTitle');
    const stepDesc = document.getElementById('stepDesc');

    if (progress < 30) {
        if (stepIcon) stepIcon.textContent = '🔍';
        if (stepTitle) stepTitle.textContent = '보안 스캔';
        if (stepDesc) stepDesc.textContent = '취약점을 검사하고 있습니다...';
    } else if (progress < 60) {
        if (stepIcon) stepIcon.textContent = '📊';
        if (stepTitle) stepTitle.textContent = '웹 표준 검사';
        if (stepDesc) stepDesc.textContent = 'HTML, CSS 표준을 검사하고 있습니다...';
    } else if (progress < 90) {
        if (stepIcon) stepIcon.textContent = '♿';
        if (stepTitle) stepTitle.textContent = '접근성 검사';
        if (stepDesc) stepDesc.textContent = '웹 접근성을 검사하고 있습니다...';
    } else {
        if (stepIcon) stepIcon.textContent = '📝';
        if (stepTitle) stepTitle.textContent = '결과 정리';
        if (stepDesc) stepDesc.textContent = '검사 결과를 정리하고 있습니다...';
    }
}

/**
 * Load scan results
 */
async function loadScanResults() {
    try {
        // 먼저 요약 API 시도 (경량 버전)
        let usingSummaryAPI = true;
        let response = await fetch(`${API_BASE_URL}/scan/${currentScanId}/summary/`);

        if (!response.ok) {
            // 요약 API가 없으면 기존 API로 폴백
            usingSummaryAPI = false;
            response = await fetch(`${API_BASE_URL}/scan/${currentScanId}/results/`);

            if (!response.ok) {
                if (response.status === 404) {
                    showError('스캔 결과를 찾을 수 없습니다.');
                    return;
                }
                throw new Error('결과 로딩 실패');
            }
        }

        const data = await response.json();

        // 전체 결과 저장
        currentResults = data;

        // Display results based on API type
        if (usingSummaryAPI) {
            displaySummaryResults(data);
            setupLazyLoading();
        } else {
            displayResults(data);
        }

    } catch (error) {
        console.error('Results loading error:', error);
        showError('결과를 불러오는 중 오류가 발생했습니다.');
    }
}

/**
 * Display scan results
 */
function displayResults(data) {
    // Hide loading, show results
    document.getElementById('loadingSection').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'block';

    // Display scan info
    if (data.url) {
        document.getElementById('scanUrl').textContent = data.url;
    }
    if (data.created_at) {
        const date = new Date(data.created_at);
        document.getElementById('scanTime').textContent = date.toLocaleString('ko-KR');
    }

    // Display security results
    if (data.security_result) {
        document.getElementById('securityScore').textContent = `${data.security_result.overall_score || 0}점`;
        displaySecurityDetails(data.security_result);
    } else {
        document.getElementById('securityScore').textContent = '-';
        document.getElementById('securityCategory').style.display = 'none';
    }

    // Display standards results
    if (data.standards_result) {
        document.getElementById('standardsScore').textContent = `${data.standards_result.overall_score || 0}점`;
        displayStandardsDetails(data.standards_result);
    } else {
        document.getElementById('standardsScore').textContent = '-';
        document.getElementById('standardsCategory').style.display = 'none';
    }

    // Display accessibility results
    if (data.accessibility_result) {
        document.getElementById('accessibilityScore').textContent = `${data.accessibility_result.overall_score || 0}점`;
        displayAccessibilityDetails(data.accessibility_result);
    } else {
        document.getElementById('accessibilityScore').textContent = '-';
        document.getElementById('accessibilityCategory').style.display = 'none';
    }
}

/**
 * Display security test details
 */
function displaySecurityDetails(result) {
    const container = document.getElementById('securityTestList');
    container.innerHTML = '';

    // 동적 메타데이터 사용 (API에서 제공)
    const tests = result.scanner_metadata || [];

    // 메타데이터가 없는 경우 기본값 사용 (하위 호환성)
    if (tests.length === 0) {
        const defaultTests = [
            { name: '보안 헤더 검사', field: 'security_headers', icon: '🛡️', id: 'security_headers' },
            { name: 'SSL/TLS 검사', field: 'ssl_tls_result', icon: '🔐', id: 'ssl_tls' },
            { name: 'XSS 취약점 스캔', field: 'xss_vulnerabilities', icon: '⚠️', id: 'xss' }
        ];
        tests.push(...defaultTests);
    }

    tests.forEach(test => {
        const testData = test.results || result[test.field];
        const item = createTestItem(test, testData, 'security', result);
        container.appendChild(item);
    });
}

/**
 * Display standards test details
 */
function displayStandardsDetails(result) {
    const container = document.getElementById('standardsTestList');
    container.innerHTML = '';

    // 동적 메타데이터 사용 (백엔드에서 제공)
    let tests = result.scanner_metadata || [];

    // 메타데이터가 없는 경우 기본값 사용 (하위 호환성)
    if (tests.length === 0) {
        tests = [
            { name: 'HTML 유효성', field: 'html_errors', icon: '📄', id: 'html_validation' },
            { name: 'CSS 유효성', field: 'css_errors', icon: '🎨', id: 'css_validation' },
            { name: 'JavaScript 검사', field: 'js_errors', icon: '⚙️', id: 'js_validation' },
            { name: 'SEO 최적화', field: 'seo_issues', icon: '🔍', id: 'seo_check' },
            { name: '성능 검사', field: 'page_performance', icon: '⚡', id: 'performance_check' }
        ];
    }

    tests.forEach(test => {
        const fieldName = test.field || test.id;
        const testData = result[fieldName];
        if (!testData && testData !== 0 && testData !== false) return;

        const item = createTestItem(test, testData, 'standards', result);
        container.appendChild(item);
    });
}

/**
 * Display accessibility test details
 */
function displayAccessibilityDetails(result) {
    const container = document.getElementById('accessibilityTestList');
    container.innerHTML = '';

    // 동적 메타데이터 사용 (백엔드에서 제공)
    let tests = result.scanner_metadata || [];

    // 메타데이터가 없는 경우 기본값 사용 (하위 호환성)
    if (tests.length === 0) {
        tests = [
            { name: '대체 텍스트', field: 'alt_text_missing', icon: '🖼️', id: 'alt_text' },
            { name: '폼 레이블', field: 'form_labels', icon: '📝', id: 'form_labels' },
            { name: '제목 구조', field: 'heading_structure', icon: '📑', id: 'heading_structure' },
            { name: 'ARIA 속성', field: 'aria', icon: '♿', id: 'aria' },
            { name: '색상 대비', field: 'contrast', icon: '🎨', id: 'contrast' },
            { name: '키보드 접근성', field: 'keyboard', icon: '⌨️', id: 'keyboard' }
        ];
    }

    tests.forEach(test => {
        const fieldName = test.field || test.id;
        const testData = result[fieldName];
        if (!testData && testData !== 0 && testData !== false) return;

        const item = createTestItem(test, testData, 'accessibility', result);
        container.appendChild(item);
    });
}

/**
 * Create test item element
 */
function createTestItem(test, testData, category, fullResult) {
    const item = document.createElement('div');
    item.className = 'test-item';
    item.dataset.testId = test.id;
    item.dataset.category = category;

    // 상태 판정
    const status = getTestStatus(testData);

    item.innerHTML = `
        <div class="test-item-left">
            <span class="test-icon">${test.icon || '🔍'}</span>
            <span class="test-name">${test.name}</span>
        </div>
        <div class="test-item-right">
            <span class="test-badge ${status.class}">${status.text}</span>
        </div>
    `;

    // 클릭 이벤트 (폴딩 대신 선택)
    item.addEventListener('click', () => {
        selectTestItem(item, test, testData, fullResult);
    });

    return item;
}

/**
 * Get test status
 */
function getTestStatus(testData) {
    if (!testData) {
        return { class: 'info', text: '데이터 없음' };
    }

    // 다양한 케이스 처리
    if (testData.has_xss || testData.has_sqli || testData.misconfigured === true) {
        const count = testData.total || testData.vulnerabilities?.length || 0;
        return { class: 'fail', text: `취약점 ${count}개` };
    }

    if (testData.missing_count > 0) {
        return { class: 'warning', text: `누락 ${testData.missing_count}개` };
    }

    if (testData.issues && testData.issues.length > 0) {
        return { class: 'warning', text: `이슈 ${testData.issues.length}개` };
    }

    if (testData.errors && testData.errors.length > 0) {
        return { class: 'warning', text: `오류 ${testData.errors.length}개` };
    }

    if (testData.status === 'warning') {
        return { class: 'warning', text: '경고' };
    }

    if (testData.status === 'fail') {
        return { class: 'fail', text: '실패' };
    }

    if (testData.is_valid === false) {
        return { class: 'warning', text: '유효하지 않음' };
    }

    if (testData.score !== undefined) {
        if (testData.score >= 80) {
            return { class: 'pass', text: `${testData.score}점` };
        } else if (testData.score >= 50) {
            return { class: 'warning', text: `${testData.score}점` };
        } else {
            return { class: 'fail', text: `${testData.score}점` };
        }
    }

    return { class: 'pass', text: '통과' };
}

/**
 * Select test item
 */
function selectTestItem(element, test, testData, fullResult) {
    // 이전 선택 제거
    document.querySelectorAll('.test-item').forEach(item => {
        item.classList.remove('active');
    });

    // 현재 선택 활성화
    element.classList.add('active');
    currentSelection = { test, testData, element, fullResult };

    // 우측 패널에 상세 정보 표시
    displayDetailedInfo(test, testData, fullResult);
}

/**
 * Display detailed information
 */
function displayDetailedInfo(test, testData, fullResult) {
    const panel = document.getElementById('detailDisplay');

    if (!testData) {
        panel.innerHTML = '<div class="no-data">데이터가 없습니다</div>';
        return;
    }

    const status = getTestStatus(testData);

    let html = `
        <div class="detail-header">
            <h2>${test.icon} ${test.name}</h2>
            <span class="detail-status ${status.class}">${status.text}</span>
        </div>

        <div class="detail-content">
    `;

    // 설명
    if (test.description) {
        html += `<div class="detail-description">${test.description}</div>`;
    }

    // 보안 취약점 상세
    if (testData.vulnerabilities && testData.vulnerabilities.length > 0) {
        html += renderVulnerabilities(testData.vulnerabilities);
    }

    // 누락된 헤더 (보안 헤더 검사)
    if (testData.headers) {
        html += renderSecurityHeaders(testData.headers);
    }

    // 웹 표준 오류
    if (testData.errors && testData.errors.length > 0) {
        html += renderValidationErrors(testData.errors);
    }

    // 접근성 이슈
    if (testData.issues && testData.issues.length > 0) {
        html += renderAccessibilityIssues(testData.issues);
    }

    // SSL/TLS 정보
    if (test.id === 'ssl_tls' && testData) {
        html += renderSSLInfo(testData);
    }

    // 권장사항
    const recommendation = testData.recommendation || test.recommendation || getDefaultRecommendation(test.id);
    if (recommendation) {
        html += `
            <div class="detail-recommendation">
                <h3>✅ 권장 조치사항</h3>
                <p>${recommendation}</p>
            </div>
        `;
    }

    html += '</div>';
    panel.innerHTML = html;
}

/**
 * Render vulnerabilities
 */
function renderVulnerabilities(vulnerabilities) {
    let html = '<div class="vulnerabilities-section">';
    html += '<h3>🚨 발견된 취약점</h3>';

    vulnerabilities.forEach(vuln => {
        const severity = vuln.severity || 'medium';
        html += `
            <div class="vuln-item severity-${severity}">
                <div class="vuln-header">
                    <span class="vuln-severity">${severity.toUpperCase()}</span>
                    <span class="vuln-title">${vuln.title || '취약점'}</span>
                </div>
                <div class="vuln-body">
                    <p>${vuln.description || ''}</p>
                    ${vuln.affected_element ?
                        `<div class="vuln-location">📍 위치: <code>${escapeHtml(vuln.affected_element)}</code></div>` : ''}
                    ${vuln.evidence ?
                        `<div class="vuln-evidence">
                            <strong>증거:</strong>
                            <pre>${escapeHtml(vuln.evidence)}</pre>
                        </div>` : ''}
                    ${vuln.recommendation ?
                        `<div class="vuln-fix">💡 해결방법: ${vuln.recommendation}</div>` : ''}
                </div>
            </div>
        `;
    });

    html += '</div>';
    return html;
}

/**
 * Render scanner details (세부 검사 항목 - 반응형 카드/테이블)
 */
function renderScannerDetails(details) {
    if (!details || details.length === 0) return '';

    let html = '<div class="scanner-details-section">';
    html += '<h3>📋 세부 검사 항목</h3>';
    html += '<div class="details-list">';

    details.forEach(item => {
        const statusClass = item.status || 'info';
        const statusBadge = getDetailStatusBadge(item.status, item.severity);
        const displayValue = item.value ? escapeHtml(String(item.value)) : null;
        const displayRecommendation = (item.status !== 'pass' && item.recommendation) ? item.recommendation : null;

        // 소속 레벨 배지 (level_label 사용)
        const levelLabel = item.level_label || '';
        const levelBadge = levelLabel ? `<span class="level-badge ${item.level || 'info'}">${levelLabel}</span>` : '';

        html += `
            <div class="detail-card status-${statusClass}">
                <div class="detail-card-header">
                    <span class="detail-card-name">${escapeHtml(item.name)}</span>
                    <div class="detail-card-badges">
                        ${levelBadge}
                        ${statusBadge}
                    </div>
                </div>
                ${item.description ? `<div class="detail-card-desc">${escapeHtml(item.description)}</div>` : ''}
                ${displayValue ? `
                    <div class="detail-card-row">
                        <span class="detail-card-label">현재 값</span>
                        <code class="detail-card-value">${displayValue}</code>
                    </div>
                ` : ''}
                ${displayRecommendation ? `
                    <div class="detail-card-row recommendation">
                        <span class="detail-card-label">권장사항</span>
                        <span class="detail-card-recommendation">${escapeHtml(displayRecommendation)}</span>
                    </div>
                ` : ''}
            </div>
        `;
    });

    html += '</div></div>';
    return html;
}

/**
 * Get status badge for detail item
 */
function getDetailStatusBadge(status, severity) {
    const badges = {
        'pass': '<span class="detail-badge pass">✓ 통과</span>',
        'fail': `<span class="detail-badge fail ${severity || 'medium'}">✗ 실패</span>`,
        'warning': '<span class="detail-badge warning">⚠ 주의</span>',
        'info': '<span class="detail-badge info">ℹ 정보</span>'
    };
    return badges[status] || `<span class="detail-badge">${status}</span>`;
}

/**
 * Render security headers
 */
function renderSecurityHeaders(headers) {
    let html = '<div class="vulnerabilities-section">';
    html += '<h3>🛡️ 보안 헤더 검사 결과</h3>';

    // 누락된 헤더
    const missingHeaders = Object.entries(headers).filter(([_, info]) => !info.present);
    if (missingHeaders.length > 0) {
        html += '<h4>누락된 헤더</h4>';
        missingHeaders.forEach(([headerName, headerInfo]) => {
            html += `
                <div class="vuln-item severity-medium">
                    <div class="vuln-header">
                        <span class="vuln-severity">${headerInfo.severity || 'MEDIUM'}</span>
                        <span class="vuln-title">${headerName}</span>
                    </div>
                    <div class="vuln-body">
                        <p>${headerInfo.description || '이 보안 헤더가 설정되지 않았습니다.'}</p>
                        ${headerInfo.recommendation ?
                            `<div class="vuln-fix">💡 권장 설정: <code>${headerInfo.recommendation}</code></div>` : ''}
                    </div>
                </div>
            `;
        });
    }

    // 설정된 헤더
    const presentHeaders = Object.entries(headers).filter(([_, info]) => info.present);
    if (presentHeaders.length > 0) {
        html += '<h4>✅ 올바르게 설정된 헤더</h4>';
        presentHeaders.forEach(([headerName, headerInfo]) => {
            html += `
                <div class="vuln-item" style="border-left: 4px solid #22c55e; background: #f0fdf4;">
                    <div class="vuln-header">
                        <span class="vuln-severity" style="background: #22c55e; color: white;">OK</span>
                        <span class="vuln-title">${headerName}</span>
                    </div>
                    <div class="vuln-body">
                        <p>현재 설정값: <code>${headerInfo.value || '설정됨'}</code></p>
                    </div>
                </div>
            `;
        });
    }

    html += '</div>';
    return html;
}

/**
 * Render validation errors
 */
function renderValidationErrors(errors) {
    let html = '<div class="vulnerabilities-section">';
    html += '<h3>⚠️ 유효성 검사 오류</h3>';

    errors.forEach(error => {
        html += `
            <div class="vuln-item severity-low">
                <div class="vuln-body">
                    <p>${error.message || error}</p>
                    ${error.line ? `<div class="vuln-location">📍 위치: Line ${error.line}</div>` : ''}
                </div>
            </div>
        `;
    });

    html += '</div>';
    return html;
}

/**
 * Render accessibility issues
 */
function renderAccessibilityIssues(issues) {
    let html = '<div class="vulnerabilities-section">';
    html += '<h3>♿ 접근성 이슈</h3>';

    issues.forEach(issue => {
        html += `
            <div class="vuln-item severity-medium">
                <div class="vuln-body">
                    <p>${issue.description || issue.message || issue}</p>
                    ${issue.element ? `<div class="vuln-location">📍 요소: <code>${escapeHtml(issue.element)}</code></div>` : ''}
                    ${issue.recommendation ? `<div class="vuln-fix">💡 권장사항: ${issue.recommendation}</div>` : ''}
                </div>
            </div>
        `;
    });

    html += '</div>';
    return html;
}

/**
 * Render SSL/TLS information
 */
function renderSSLInfo(data) {
    let html = '<div class="vulnerabilities-section">';
    html += '<h3>🔐 SSL/TLS 정보</h3>';

    if (data.https === false) {
        html += `
            <div class="vuln-item severity-high">
                <div class="vuln-header">
                    <span class="vuln-severity">HIGH</span>
                    <span class="vuln-title">HTTPS 미사용</span>
                </div>
                <div class="vuln-body">
                    <p>웹사이트가 암호화되지 않은 HTTP를 사용하고 있습니다.</p>
                    <div class="vuln-fix">💡 SSL 인증서를 설치하고 HTTPS를 활성화하세요.</div>
                </div>
            </div>
        `;
    } else {
        html += `
            <div class="vuln-item" style="border-left: 4px solid #22c55e; background: #f0fdf4;">
                <div class="vuln-header">
                    <span class="vuln-severity" style="background: #22c55e; color: white;">OK</span>
                    <span class="vuln-title">HTTPS 사용 중</span>
                </div>
                <div class="vuln-body">
                    <p>웹사이트가 SSL/TLS로 안전하게 암호화되어 있습니다.</p>
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

/**
 * Get default recommendation
 */
function getDefaultRecommendation(testId) {
    const recommendations = {
        'xss': 'Todos os dados de entrada devem ser validados e sanitizados. Use funções de escape apropriadas para o contexto de saída.',
        'sql_injection': 'Use prepared statements ou stored procedures. Nunca concatene strings diretamente nas queries SQL.',
        'security_headers': '모든 보안 헤더를 올바르게 설정하세요. Content-Security-Policy, X-Frame-Options, X-Content-Type-Options 등을 포함해야 합니다.',
        'cors': 'CORS 설정을 검토하고, 신뢰할 수 있는 도메인만 허용하세요.',
        'csrf': 'CSRF 토큰을 모든 상태 변경 요청에 포함시키세요.',
        'ssl_tls': 'SSL/TLS 인증서를 설치하고 모든 트래픽을 HTTPS로 리다이렉트하세요.',
        'cookie': '쿠키에 Secure, HttpOnly, SameSite 속성을 설정하세요.',
        'html_validation': 'W3C 표준에 맞게 HTML을 작성하세요. 유효성 검사 도구를 사용하여 오류를 수정하세요.',
        'css_validation': 'CSS 문법 오류를 수정하고, 벤더 프리픽스를 적절히 사용하세요.',
        'performance': '이미지 최적화, 코드 압축, 캐싱 전략을 구현하세요.',
        'seo': '메타 태그 최적화, 구조화된 데이터 추가, 사이트맵 생성을 고려하세요.',
        'alt_text': '모든 이미지에 의미 있는 대체 텍스트를 제공하세요.',
        'form_labels': '모든 폼 요소에 명확한 레이블을 연결하세요.',
        'heading_structure': '논리적인 제목 계층 구조를 사용하세요 (h1 → h2 → h3).',
        'aria': 'ARIA 속성을 올바르게 사용하여 스크린 리더 접근성을 개선하세요.',
        'contrast': '텍스트와 배경 간의 충분한 색상 대비를 확보하세요 (WCAG 기준).',
        'keyboard': '모든 인터랙티브 요소가 키보드로 접근 가능하도록 하세요.'
    };

    return recommendations[testId] || '웹 표준과 보안 모범 사례를 따라 수정하세요.';
}

/**
 * Escape HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Handle keyboard navigation
 */
function handleKeyboardNavigation(e) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        navigateTestItems(e.key === 'ArrowDown' ? 1 : -1);
    }
}

/**
 * Navigate test items
 */
function navigateTestItems(direction) {
    const items = Array.from(document.querySelectorAll('.test-item'));
    if (items.length === 0) return;

    const currentIndex = items.findIndex(item => item.classList.contains('active'));
    let nextIndex;

    if (currentIndex === -1) {
        // 선택된 항목이 없으면 첫 번째 또는 마지막 선택
        nextIndex = direction > 0 ? 0 : items.length - 1;
    } else {
        nextIndex = currentIndex + direction;
        // 순환하지 않도록 제한
        if (nextIndex < 0) nextIndex = 0;
        if (nextIndex >= items.length) nextIndex = items.length - 1;
    }

    if (items[nextIndex] && nextIndex !== currentIndex) {
        items[nextIndex].click();
        items[nextIndex].scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
}

/**
 * Show loading state
 */
function showLoading(statusData) {
    document.getElementById('loadingSection').style.display = 'block';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('errorSection').style.display = 'none';

    // Update progress if available
    if (statusData && statusData.progress !== undefined) {
        updateProgress(statusData.progress);
    }
}

/**
 * Show error state
 */
function showError(message) {
    document.getElementById('loadingSection').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('errorSection').style.display = 'block';

    const errorMsg = document.getElementById('errorMessage');
    if (errorMsg) {
        errorMsg.textContent = message;
    }
}

/**
 * Share scan results
 */
function shareScanResults() {
    const url = window.location.href;

    // Copy to clipboard
    navigator.clipboard.writeText(url).then(() => {
        // Show toast notification
        showToast('결과 페이지 URL이 클립보드에 복사되었습니다.');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showToast('URL 복사에 실패했습니다.', 'error');
    });
}

/**
 * Show toast notification
 */
function showToast(message, type = 'success') {
    // Remove existing toast
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }

    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 24px;
        background: ${type === 'success' ? '#10b981' : '#ef4444'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(toast);

    // Remove after 3 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Add toast animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }

    .detail-loading {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 40px;
        color: #666;
    }

    .detail-error {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 40px;
        color: #ef4444;
    }
`;
document.head.appendChild(style);

// ===== New functions for Summary API and Lazy Loading =====

// Cache for scanner details
const detailCache = {};

/**
 * Display summary results (lightweight version)
 */
function displaySummaryResults(data) {
    // Hide loading, show results
    document.getElementById('loadingSection').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'block';

    // Display scan info
    if (data.url) {
        document.getElementById('scanUrl').textContent = data.url;
    }
    if (data.created_at) {
        const date = new Date(data.created_at);
        document.getElementById('scanTime').textContent = date.toLocaleString('ko-KR');
    }

    // Display security summary
    if (data.security_summary) {
        const summary = data.security_summary;
        document.getElementById('securityScore').textContent = `${summary.overall_score || 0}점`;
        displaySecuritySummary(summary);
    } else {
        document.getElementById('securityScore').textContent = '-';
    }

    // Display standards summary
    if (data.standards_summary) {
        const summary = data.standards_summary;
        document.getElementById('standardsScore').textContent = `${summary.overall_score || 0}점`;
        displayStandardsSummary(summary);
    } else {
        document.getElementById('standardsScore').textContent = '-';
        document.getElementById('standardsCategory').style.display = 'none';
    }

    // Display accessibility summary
    if (data.accessibility_summary) {
        const summary = data.accessibility_summary;
        document.getElementById('accessibilityScore').textContent = `${summary.overall_score || 0}점`;
        displayAccessibilitySummary(summary);
    } else {
        document.getElementById('accessibilityScore').textContent = '-';
        document.getElementById('accessibilityCategory').style.display = 'none';
    }
}

/**
 * Display security summary (scanners list only)
 */
function displaySecuritySummary(summary) {
    const container = document.getElementById('securityTestList');
    container.innerHTML = '';

    // Use scanners list from summary
    const scanners = summary.scanners || [];

    scanners.forEach(scanner => {
        const item = createSummaryTestItem(scanner, 'security');
        container.appendChild(item);
    });
}

/**
 * Display standards summary (scanners list only)
 */
function displayStandardsSummary(summary) {
    const container = document.getElementById('standardsTestList');
    container.innerHTML = '';

    // Use scanners list from summary
    const scanners = summary.scanners || [];

    scanners.forEach(scanner => {
        const item = createSummaryTestItem(scanner, 'standards');
        container.appendChild(item);
    });
}

/**
 * Display accessibility summary (scanners list only)
 */
function displayAccessibilitySummary(summary) {
    const container = document.getElementById('accessibilityTestList');
    container.innerHTML = '';

    // Use scanners list from summary
    const scanners = summary.scanners || [];

    scanners.forEach(scanner => {
        const item = createSummaryTestItem(scanner, 'accessibility');
        container.appendChild(item);
    });
}

/**
 * Create summary test item (lightweight version)
 */
function createSummaryTestItem(scanner, category) {
    const item = document.createElement('div');
    item.className = 'test-item';
    item.dataset.testId = scanner.id;
    item.dataset.category = category;

    // Set badge based on status
    let badgeClass = 'pass';
    let badgeText = '통과';

    if (scanner.status === 'skipped') {
        badgeClass = 'skipped';
        badgeText = '스킵';
    } else if (scanner.status === 'not_applicable') {
        badgeClass = 'not-applicable';
        badgeText = '해당없음';
    } else if (scanner.status === 'fail') {
        if (scanner.severity === 'critical') {
            badgeClass = 'critical';
            badgeText = `치명적 ${scanner.count}개`;
        } else if (scanner.severity === 'high') {
            badgeClass = 'danger';
            badgeText = `높음 ${scanner.count}개`;
        } else if (scanner.severity === 'medium') {
            badgeClass = 'warning';
            badgeText = `중간 ${scanner.count}개`;
        } else {
            badgeClass = 'info';
            badgeText = `낮음 ${scanner.count}개`;
        }
    } else if (scanner.status === 'pass') {
        // 통과 시 checked/passed 값이 있으면 상세 표시
        if (scanner.checked && scanner.checked > 0) {
            badgeText = `통과 ${scanner.passed}/${scanner.checked}`;
        }
    }

    item.innerHTML = `
        <div class="test-item-left">
            <span class="test-icon">${scanner.icon || '🔍'}</span>
            <span class="test-name">${scanner.name}</span>
        </div>
        <div class="test-item-right">
            <span class="test-badge ${badgeClass}">${badgeText}</span>
        </div>
    `;

    // Click event for loading details
    item.addEventListener('click', () => {
        selectTestItem(item);
        loadAndDisplayScannerDetail(scanner.id);
    });

    return item;
}

/**
 * Setup lazy loading for detail information
 */
function setupLazyLoading() {
    // Lazy loading 설정 완료
}

/**
 * Load and display scanner detail (Lazy Loading)
 */
async function loadAndDisplayScannerDetail(scannerId) {
    // Check cache first
    if (detailCache[scannerId]) {
        displayEnhancedDetailedInfo(detailCache[scannerId]);
        return;
    }

    try {
        // Show loading state
        const detailDisplay = document.getElementById('detailDisplay');
        if (detailDisplay) {
            detailDisplay.innerHTML = '<div class="detail-loading">🔍 상세 정보를 불러오는 중...</div>';
        }

        // Call individual scanner detail API
        const response = await fetch(`${API_BASE_URL}/scan/${currentScanId}/scanner/?scanner_id=${scannerId}`);

        if (!response.ok) {
            throw new Error('상세 정보를 불러올 수 없습니다.');
        }

        const detailData = await response.json();

        // Save to cache
        detailCache[scannerId] = detailData;

        // Display enhanced detailed info
        displayEnhancedDetailedInfo(detailData);

    } catch (error) {
        console.error('Detail loading error:', error);
        const detailDisplay = document.getElementById('detailDisplay');
        if (detailDisplay) {
            detailDisplay.innerHTML = '<div class="detail-error">⚠️ 상세 정보를 불러올 수 없습니다.</div>';
        }
    }
}

/**
 * Display enhanced detailed information (with OWASP, CWE, guide, etc.)
 */
function displayEnhancedDetailedInfo(detail) {
    const container = document.getElementById('detailDisplay');
    if (!container) return;

    // Build enhanced HTML
    let html = `
        <div class="detail-header">
            <h2>${detail.icon || '🔍'} ${detail.name || detail.scanner_id}</h2>
            <div class="detail-badges">
                <span class="detail-status ${detail.status || 'unknown'}">${detail.status === 'pass' ? '✅ 통과' : '⚠️ 이슈 발견'}</span>
                ${detail.severity && detail.status !== 'pass' ? `<span class="severity-badge ${detail.severity}">${detail.severity.toUpperCase()}</span>` : ''}
            </div>
        </div>

        <div class="detail-content">
    `;

    // Description
    if (detail.description || detail.guide?.description) {
        html += `
            <div class="detail-description">
                <p>${detail.description || detail.guide.description}</p>
            </div>
        `;
    }

    // Statistics
    if (detail.statistics) {
        const stats = detail.statistics;
        const labels = stats.labels || {
            critical: '긴급', high: '위험', medium: '주의', low: '유의', info: '정보'
        };

        html += `
            <div class="detail-statistics">
                <h3>📊 검사 통계</h3>
                <div class="stats-grid">
                    <div class="stat-item total">
                        <span class="stat-label">총 항목</span>
                        <span class="stat-value">${stats.total_checked || 0}</span>
                    </div>
                    <div class="stat-item passed">
                        <span class="stat-label">통과</span>
                        <span class="stat-value passed">${stats.passed_count || 0}</span>
                    </div>
                    ${stats.critical_count ? `<div class="stat-item">
                        <span class="stat-label">${labels.critical}</span>
                        <span class="stat-value critical">${stats.critical_count}</span>
                    </div>` : ''}
                    ${stats.high_count ? `<div class="stat-item">
                        <span class="stat-label">${labels.high}</span>
                        <span class="stat-value high">${stats.high_count}</span>
                    </div>` : ''}
                    ${stats.medium_count ? `<div class="stat-item">
                        <span class="stat-label">${labels.medium}</span>
                        <span class="stat-value medium">${stats.medium_count}</span>
                    </div>` : ''}
                    ${stats.low_count ? `<div class="stat-item">
                        <span class="stat-label">${labels.low}</span>
                        <span class="stat-value low">${stats.low_count}</span>
                    </div>` : ''}
                    ${stats.info_count ? `<div class="stat-item">
                        <span class="stat-label">${labels.info}</span>
                        <span class="stat-value info">${stats.info_count}</span>
                    </div>` : ''}
                </div>
            </div>
        `;
    }

    // Details (세부 검사 항목) - 먼저 표시
    if (detail.details && detail.details.length > 0) {
        html += renderScannerDetails(detail.details);
    }

    // Vulnerabilities list
    if (detail.vulnerabilities && detail.vulnerabilities.length > 0) {
        html += renderVulnerabilities(detail.vulnerabilities);
    }

    // Guide - Remediation steps
    if (detail.guide?.remediation?.steps) {
        html += `
            <div class="detail-remediation">
                <h3>✅ 권장 조치사항</h3>
                <ol>
                    ${detail.guide.remediation.steps.map(step => `<li>${step}</li>`).join('')}
                </ol>
            </div>
        `;
    }

    // OWASP & CWE information
    if (detail.guide?.owasp || detail.guide?.cwe) {
        html += `
            <div class="detail-compliance">
                <h3>📋 표준 매핑</h3>
                <div class="compliance-tags">
                    ${detail.guide?.owasp ? detail.guide.owasp.map(o => `<span class="owasp-tag">${o}</span>`).join('') : ''}
                    ${detail.guide?.cwe ? detail.guide.cwe.map(c => `<span class="cwe-tag">${c}</span>`).join('') : ''}
                </div>
            </div>
        `;
    }

    // References
    if (detail.guide?.references && detail.guide.references.length > 0) {
        html += `
            <div class="detail-references">
                <h3>📚 참고 자료</h3>
                <ul>
                    ${detail.guide.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
                </ul>
            </div>
        `;
    }

    // For passed tests - show best practices
    if (detail.status === 'pass') {
        html += `
            <div class="detail-passed">
                <h3>✅ 검사 결과</h3>
                <p>이 항목의 모든 보안 검사를 통과했습니다.</p>
                ${detail.guide?.remediation?.steps ? `
                    <div class="best-practices">
                        <h4>추가 개선 권장사항:</h4>
                        <ul>
                            ${detail.guide.remediation.steps.slice(0, 3).map(step => `<li>${step}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
    }

    html += '</div>'; // Close detail-content

    container.innerHTML = html;
}
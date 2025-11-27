/**
 * Weak Scanner - Frontend JavaScript
 * Handles API interaction, real-time updates, and result visualization
 */

// Global variables
let currentScanId = null;
let statusPollInterval = null;

// API Base URL
const API_BASE_URL = '/api';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
});

/**
 * Initialize event listeners
 */
function initializeEventListeners() {
    const scanForm = document.getElementById('scanForm');
    const newScanBtn = document.getElementById('newScanBtn');
    const tabButtons = document.querySelectorAll('.tab-btn');

    scanForm.addEventListener('submit', handleScanSubmit);
    newScanBtn.addEventListener('click', resetToScanForm);

    tabButtons.forEach(btn => {
        btn.addEventListener('click', (e) => switchTab(e.target.dataset.tab));
    });
}

/**
 * Handle scan form submission
 */
async function handleScanSubmit(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const url = formData.get('url');
    const scanTypes = formData.getAll('scan_types');
    const deepScan = formData.get('deep_scan') === 'on';

    // Validate
    if (!url) {
        alert('URL을 입력해주세요.');
        return;
    }

    if (scanTypes.length === 0) {
        alert('최소 하나의 스캔 유형을 선택해주세요.');
        return;
    }

    // Prepare request data
    const requestData = {
        url: url,
        scan_types: scanTypes,
        deep_scan: deepScan
    };

    // Immediately show progress section and disable button
    showProgressSection();
    const scanBtn = document.getElementById('scanBtn');
    scanBtn.disabled = true;

    // Use setTimeout to ensure UI updates before API call
    setTimeout(async () => {
        try {
            console.log('Starting API call...');

            // Call API
            const response = await fetch(`${API_BASE_URL}/scan/start/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestData)
            });

            console.log('API response received');
            const data = await response.json();

            if (!response.ok) {
                // 429 Too Many Requests 특별 처리
                if (response.status === 429) {
                    const currentScans = data.current_scans || '?';
                    const maxAllowed = data.max_allowed || '?';
                    const message = data.message || '현재 스캔이 많이 실행 중입니다. 잠시 후 다시 시도해주세요.';

                    alert(`⏳ 동시 스캔 제한 초과\n\n${message}\n\n현재 실행 중: ${currentScans}개\n최대 허용: ${maxAllowed}개`);

                    // Reset to Step 1 and return (no throw to avoid duplicate alert)
                    resetToScanForm();
                    return;
                }

                throw new Error(data.error || data.details || '스캔 요청 실패');
            }

            // Store scan ID and start polling
            currentScanId = data.scan_id;
            console.log('Scan ID:', currentScanId);

            // Start polling for status
            startStatusPolling();

        } catch (error) {
            console.error('Scan request error:', error);
            alert(`스캔 요청 실패: ${error.message}`);

            // Reset to Step 1 on error
            resetToScanForm();
        }
    }, 100); // Small delay to ensure UI updates
}

/**
 * Show progress section (Step 2)
 */
function showProgressSection() {
    console.log('Showing progress section - Step 2');

    // Hide all steps first
    document.querySelectorAll('.wizard-step').forEach(step => {
        step.classList.remove('active');
        step.style.display = 'none';
    });

    // Show step 2
    const step2 = document.getElementById('step2');
    if (step2) {
        step2.classList.add('active');
        step2.style.display = 'block';
        console.log('Step 2 is now visible');
    } else {
        console.error('Step 2 element not found!');
    }

    // Reset progress bar to 0%
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    if (progressFill) {
        progressFill.style.width = '0%';
    }
    if (progressText) {
        progressText.textContent = '0%';
    }

    resetLoadingSteps();
}

/**
 * Start polling for scan status
 */
function startStatusPolling() {
    // Clear any existing interval
    if (statusPollInterval) {
        clearInterval(statusPollInterval);
    }

    console.log('Starting status polling...');

    // Wait a bit before first poll to ensure UI is visible
    setTimeout(() => {
        updateScanStatus();
    }, 1000);

    // Then poll every 2 seconds
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

        console.log('Scan status:', data.status, 'Progress:', data.progress + '%');

        // Update progress bar
        updateProgressBar(data.progress);

        // Update status text
        updateStatusText(data.status, data.progress);

        // Check if completed
        if (data.status === 'completed') {
            console.log('Scan completed! Loading results...');
            clearInterval(statusPollInterval);
            await loadScanResults();
        } else if (data.status === 'failed') {
            console.error('Scan failed:', data.error_message);
            clearInterval(statusPollInterval);
            alert(`스캔 실패: ${data.error_message || '알 수 없는 오류'}`);
            resetToScanForm();
        } else {
            console.log('Scan still running...');
        }

    } catch (error) {
        console.error('Status poll error:', error);
    }
}

/**
 * Update progress bar
 */
function updateProgressBar(progress) {
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');

    progressFill.style.width = `${progress}%`;
    progressText.textContent = `${progress}%`;

    // Update loading steps based on progress
    updateLoadingSteps(progress);
}

/**
 * Update status text
 */
function updateStatusText(status, progress) {
    // Status text is now handled by loading steps
    updateLoadingSteps(progress);
}

/**
 * Load scan results
 */
async function loadScanResults() {
    try {
        const response = await fetch(`${API_BASE_URL}/scan/${currentScanId}/results/`);

        if (response.status === 202) {
            // Still processing
            return;
        }

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || '결과 로드 실패');
        }

        // Display results
        displayResults(data);

    } catch (error) {
        console.error('Results load error:', error);
        alert(`결과 로드 실패: ${error.message}`);
    }
}

/**
 * Display scan results
 */
function displayResults(data) {
    console.log('Displaying results - Step 3');

    // Hide all steps first
    document.querySelectorAll('.wizard-step').forEach(step => {
        step.classList.remove('active');
        step.style.display = 'none';
    });

    // Show step 3
    const step3 = document.getElementById('step3');
    if (step3) {
        step3.classList.add('active');
        step3.style.display = 'block';
        console.log('Step 3 is now visible');
    } else {
        console.error('Step 3 element not found!');
    }

    // Display scores
    if (data.security_result) {
        document.getElementById('securityScore').textContent = `${data.security_result.overall_score || 0}점`;
        displaySecurityDetails(data.security_result);
    } else {
        document.getElementById('securityScore').textContent = '-';
        document.getElementById('securityDetails').style.display = 'none';
    }

    if (data.standards_result) {
        document.getElementById('standardsScore').textContent = `${data.standards_result.overall_score || 0}점`;
        displayStandardsDetails(data.standards_result);
    } else {
        document.getElementById('standardsScore').textContent = '-';
        document.getElementById('standardsDetails').style.display = 'none';
    }

    if (data.accessibility_result) {
        document.getElementById('accessibilityScore').textContent = `${data.accessibility_result.overall_score || 0}점`;
        displayAccessibilityDetails(data.accessibility_result);
    } else {
        document.getElementById('accessibilityScore').textContent = '-';
        document.getElementById('accessibilityDetails').style.display = 'none';
    }
}

/**
 * Toggle details section visibility
 */
function toggleDetails(headerElement) {
    const parent = headerElement.closest('.step3-test-item');
    const details = parent.querySelector('.step3-test-details');
    const icon = parent.querySelector('.step3-expand-icon');

    if (details) {
        if (details.style.display === 'none' || !details.style.display) {
            details.style.display = 'block';
            if (icon) icon.textContent = '▲';
        } else {
            details.style.display = 'none';
            if (icon) icon.textContent = '▼';
        }
    }
}

/**
 * Get severity label in Korean
 */
function getSeverityLabel(severity) {
    const labels = {
        'critical': '치명적',
        'high': '높음',
        'medium': '중간',
        'low': '낮음',
        'info': '정보'
    };
    return labels[severity] || severity;
}

/**
 * Get accessibility recommendation based on issue type
 */
function getAccessibilityRecommendation(testId, issue) {
    const recommendations = {
        'alt_text': '모든 이미지에 적절한 alt 속성을 추가하세요. 장식용 이미지는 alt=""로 설정하세요.',
        'form_labels': '모든 폼 요소에 명확한 label을 연결하세요. label 태그를 사용하거나 aria-label 속성을 추가하세요.',
        'heading': '논리적인 제목 구조를 사용하세요. h1부터 순서대로 사용하고 레벨을 건너뛰지 마세요.',
        'aria': 'ARIA 속성을 올바르게 사용하세요. role, aria-label, aria-describedby 등을 적절히 활용하세요.',
        'contrast': '텍스트와 배경 간의 색상 대비를 WCAG 기준(일반 텍스트 4.5:1, 큰 텍스트 3:1) 이상으로 조정하세요.',
        'keyboard': '모든 인터랙티브 요소가 키보드로 접근 가능하도록 하세요. tabindex와 키보드 이벤트를 적절히 처리하세요.',
        'screen_reader': '스크린리더 사용자를 위해 숨겨진 텍스트나 aria-live 영역을 활용하여 동적 콘텐츠 변경을 알리세요.'
    };

    if (issue.recommendation) {
        return issue.recommendation;
    }

    return recommendations[testId] || '웹 접근성 지침(WCAG)을 준수하여 수정하세요.';
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
            { name: 'XSS 취약점 스캔', field: 'xss_vulnerabilities', icon: '⚠️', id: 'xss' },
            { name: 'SQL Injection 스캔', field: 'sql_injection', icon: '💉', id: 'sql_injection' },
            { name: 'CORS 설정 검사', field: 'cors_misconfiguration', icon: '🌐', id: 'cors' },
            { name: '쿠키 보안 검사', field: 'sensitive_data_exposure', icon: '🍪', id: 'cookie' },
            { name: 'CSRF 보호 검사', field: 'csrf_protection', icon: '🔒', id: 'csrf' },
            { name: '클릭재킹 방어 검사', field: 'clickjacking', icon: '🖱️', id: 'clickjacking' },
            { name: '정보 노출 검사', field: 'insufficient_logging', icon: '📝', id: 'info_disclosure' },
            { name: 'HTTP 메서드 검사', field: 'http_methods', icon: '📡', id: 'http_methods' },
            { name: '민감한 파일 노출 검사', field: 'sensitive_files', icon: '📁', id: 'sensitive_files' },
            { name: 'Mixed Content 검사', field: 'mixed_content', icon: '🔗', id: 'mixed_content' },
            { name: 'SRI 검사', field: 'sri_check', icon: '✓', id: 'sri' },
            { name: '디렉토리 리스팅 검사', field: 'directory_listing', icon: '📂', id: 'directory_listing' },
            { name: 'Open Redirect 검사', field: 'open_redirects', icon: '↗️', id: 'open_redirect' }
        ];
        tests.push(...defaultTests);
    }

    tests.forEach(test => {
        // 메타데이터에서 결과 가져오기
        const testData = test.results || result[test.field];
        const item = document.createElement('div');
        item.className = 'step3-test-item';

        let status = '✓';
        let statusClass = 'pass';
        let badgeText = '통과';
        let hasDetails = false;

        // Analyze test results
        if (testData) {
            if (testData.has_xss || testData.has_sqli) {
                status = '✗';
                statusClass = 'fail';
                badgeText = `취약점 ${testData.total || 0}개`;
                hasDetails = testData.vulnerabilities && testData.vulnerabilities.length > 0;
            } else if (testData.misconfigured === true) {
                status = '⚠️';
                statusClass = 'warning';
                badgeText = '설정 오류';
                hasDetails = testData.issues && testData.issues.length > 0;
            } else if (testData.missing_count > 0) {
                status = '⚠️';
                statusClass = 'warning';
                badgeText = `누락 ${testData.missing_count}개`;
                hasDetails = true; // 보안 헤더는 항상 상세 정보 있음
            } else if (testData.status === 'warning') {
                status = '⚠️';
                statusClass = 'warning';
                badgeText = '경고';
                hasDetails = testData.issues && testData.issues.length > 0;
            } else if (testData.status === 'ok' || testData.https === true) {
                status = '✓';
                statusClass = 'pass';
                badgeText = '통과';
                hasDetails = true; // 통과한 경우에도 상세 정보 표시
            } else if (testData.issues && testData.issues.length > 0) {
                status = '⚠️';
                statusClass = 'warning';
                badgeText = `이슈 ${testData.issues.length}개`;
                hasDetails = true;
            }
        }

        // Create item header with expandable functionality
        const headerHTML = `
            <div class="step3-test-header" ${hasDetails ? 'onclick="toggleDetails(this)"' : ''}>
                <div class="step3-test-status">${test.icon || '🔍'}</div>
                <div class="step3-test-name">
                    ${test.name || test.description || '테스트'}
                    ${hasDetails ? '<span class="step3-expand-icon">▼</span>' : ''}
                </div>
                <div class="step3-test-result">
                    <span class="step3-test-badge ${statusClass}">${badgeText}</span>
                </div>
            </div>
        `;

        item.innerHTML = headerHTML;

        // Add detailed information section
        if (hasDetails && testData) {
            const detailsDiv = document.createElement('div');
            detailsDiv.className = 'step3-test-details';
            detailsDiv.style.display = 'none';

            // Security Headers 상세 정보
            if (test.id === 'security_headers' && testData.headers) {
                let detailsHTML = '<div class="step3-details-content">';

                // 누락된 헤더 표시
                const missingHeaders = Object.entries(testData.headers).filter(([_, info]) => !info.present);
                if (missingHeaders.length > 0) {
                    missingHeaders.forEach(([headerName, headerInfo]) => {
                        detailsHTML += `
                            <div class="step3-detail-item">
                                <div class="step3-detail-header">
                                    <span class="step3-severity-badge ${headerInfo.severity || 'medium'}">
                                        ${getSeverityLabel(headerInfo.severity || 'medium')}
                                    </span>
                                    <strong>${headerName}</strong>
                                </div>
                                <div class="step3-detail-desc">${headerInfo.description || '보안 헤더가 설정되지 않았습니다.'}</div>
                                <div class="step3-detail-recommendation">
                                    <code>${headerInfo.recommendation || `${headerName}: [appropriate-value]`}</code>
                                </div>
                            </div>
                        `;
                    });
                }

                // 올바르게 설정된 헤더도 자세히 표시
                const presentHeaders = Object.entries(testData.headers).filter(([_, info]) => info.present);
                if (presentHeaders.length > 0) {
                    presentHeaders.forEach(([headerName, headerInfo]) => {
                        detailsHTML += `
                            <div class="step3-detail-item step3-detail-success">
                                <div class="step3-detail-header">
                                    <span class="step3-severity-badge success">✓ 설정됨</span>
                                    <strong>${headerName}</strong>
                                </div>
                                <div class="step3-detail-desc">
                                    ${headerInfo.value ? `현재 설정값: <code>${headerInfo.value}</code><br>` : ''}
                                    ${headerInfo.description || '보안 헤더가 올바르게 설정되어 있습니다.'}
                                </div>
                            </div>
                        `;
                    });
                }

                // 검사 요약 정보
                detailsHTML += `
                    <div class="step3-detail-item step3-detail-info">
                        <div class="step3-detail-header">
                            <strong>검사 요약</strong>
                        </div>
                        <div class="step3-detail-desc">
                            총 ${Object.keys(testData.headers).length}개 헤더 검사<br>
                            ✓ 설정됨: ${presentHeaders.length}개<br>
                            ✗ 누락됨: ${missingHeaders.length}개
                        </div>
                    </div>
                `;

                detailsHTML += '</div>';
                detailsDiv.innerHTML = detailsHTML;
            }
            // XSS/SQL Injection 상세 정보
            else if ((test.id === 'xss' || test.id === 'sql_injection') && testData) {
                let detailsHTML = '<div class="step3-details-content">';

                if (testData.vulnerabilities && testData.vulnerabilities.length > 0) {
                    // 취약점이 발견된 경우
                    testData.vulnerabilities.forEach(vuln => {
                        detailsHTML += `
                            <div class="step3-detail-item">
                                <div class="step3-detail-header">
                                    <span class="step3-severity-badge ${vuln.severity || 'high'}">
                                        ${getSeverityLabel(vuln.severity || 'high')}
                                    </span>
                                    <strong>${vuln.type || '취약점'}</strong>
                                </div>
                                ${vuln.parameter ? `<div class="step3-detail-param">파라미터: <code>${vuln.parameter}</code></div>` : ''}
                                ${vuln.description ? `<div class="step3-detail-desc">${vuln.description}</div>` : ''}
                                ${vuln.payload ? `<div class="step3-detail-evidence">테스트 페이로드: <code>${vuln.payload}</code></div>` : ''}
                                ${vuln.recommendation ? `
                                    <div class="step3-detail-recommendation">
                                        <strong>해결 방법:</strong><br>
                                        ${vuln.recommendation}
                                    </div>
                                ` : ''}
                            </div>
                        `;
                    });
                } else {
                    // 취약점이 없는 경우 (통과)
                    const testName = test.id === 'xss' ? 'XSS' : 'SQL Injection';
                    detailsHTML += `
                        <div class="step3-detail-item step3-detail-success">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge success">✓ 안전</span>
                                <strong>${testName} 보안 검사 통과</strong>
                            </div>
                            <div class="step3-detail-desc">
                                다음 항목들을 검사하여 취약점이 발견되지 않았습니다:<br>
                                ${test.id === 'xss' ? `
                                    • 반사형 XSS (Reflected XSS)<br>
                                    • DOM 기반 XSS<br>
                                    • 입력 필드 스크립트 삽입<br>
                                    • HTML 태그 삽입<br>
                                    • JavaScript 이벤트 핸들러 삽입
                                ` : `
                                    • SQL 쿼리 삽입<br>
                                    • Union 기반 공격<br>
                                    • Boolean 기반 블라인드 공격<br>
                                    • Time 기반 블라인드 공격<br>
                                    • Error 기반 공격
                                `}
                            </div>
                        </div>
                    `;

                    if (testData.tests_performed) {
                        detailsHTML += `
                            <div class="step3-detail-item step3-detail-info">
                                <div class="step3-detail-header">
                                    <strong>검사 상세</strong>
                                </div>
                                <div class="step3-detail-desc">
                                    테스트한 파라미터 수: ${testData.parameters_tested || 0}개<br>
                                    사용된 페이로드 수: ${testData.payloads_used || 0}개<br>
                                    검사 완료 시간: ${testData.scan_time || 'N/A'}
                                </div>
                            </div>
                        `;
                    }
                }

                detailsHTML += '</div>';
                detailsDiv.innerHTML = detailsHTML;
            }
            // 기타 취약점 상세 정보 (vulnerabilities 배열이 있는 경우)
            else if (testData && testData.vulnerabilities && testData.vulnerabilities.length > 0) {
                let detailsHTML = '<div class="step3-details-content">';

                testData.vulnerabilities.forEach(vuln => {
                    detailsHTML += `
                        <div class="step3-detail-item">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge ${vuln.severity || 'high'}">
                                    ${getSeverityLabel(vuln.severity || 'high')}
                                </span>
                                <strong>${vuln.type || '취약점'}</strong>
                            </div>
                            ${vuln.parameter ? `<div class="step3-detail-param">파라미터: <code>${vuln.parameter}</code></div>` : ''}
                            ${vuln.description ? `<div class="step3-detail-desc">${vuln.description}</div>` : ''}
                            ${vuln.payload ? `<div class="step3-detail-evidence">테스트 페이로드: <code>${vuln.payload}</code></div>` : ''}
                            ${vuln.recommendation ? `
                                <div class="step3-detail-recommendation">
                                    <strong>해결 방법:</strong><br>
                                    ${vuln.recommendation}
                                </div>
                            ` : ''}
                        </div>
                    `;
                });

                detailsHTML += '</div>';
                detailsDiv.innerHTML = detailsHTML;
            }
            // CORS/쿠키/기타 설정 오류 상세 정보
            else if ((test.id === 'cors_policy' || test.id === 'cookie_security' || test.id === 'csrf_protection') && testData) {
                let detailsHTML = '<div class="step3-details-content">';

                if (testData.issues && testData.issues.length > 0) {
                    // 이슈가 있는 경우
                    testData.issues.forEach(issue => {
                        detailsHTML += `
                            <div class="step3-detail-item">
                                <div class="step3-detail-header">
                                    <span class="step3-severity-badge ${issue.severity || 'medium'}">
                                        ${getSeverityLabel(issue.severity || 'medium')}
                                    </span>
                                    <strong>${issue.type || issue.name || '이슈'}</strong>
                                </div>
                                <div class="step3-detail-desc">${issue.description || issue.message || '설정 문제가 발견되었습니다.'}</div>
                                ${issue.recommendation ? `
                                    <div class="step3-detail-recommendation">
                                        ${issue.recommendation}
                                    </div>
                                ` : ''}
                            </div>
                        `;
                    });
                } else {
                    // 이슈가 없는 경우 (통과)
                    let testTitle = '';
                    let checkedItems = '';

                    if (test.id === 'cors_policy') {
                        testTitle = 'CORS 정책 검사';
                        checkedItems = `
                            • Access-Control-Allow-Origin 헤더 설정 확인<br>
                            • 와일드카드(*) 사용 여부 검사<br>
                            • Access-Control-Allow-Credentials 설정 검증<br>
                            • Preflight 요청 처리 확인<br>
                            • 허용된 메서드 및 헤더 검증
                        `;
                    } else if (test.id === 'cookie_security') {
                        testTitle = '쿠키 보안 검사';
                        checkedItems = `
                            • Secure 플래그 설정 확인<br>
                            • HttpOnly 플래그 설정 확인<br>
                            • SameSite 속성 검증<br>
                            • 쿠키 만료 시간 확인<br>
                            • 세션 쿠키 보안 설정 검증
                        `;
                    } else if (test.id === 'csrf_protection') {
                        testTitle = 'CSRF 방어 검사';
                        checkedItems = `
                            • CSRF 토큰 존재 여부 확인<br>
                            • 토큰 검증 메커니즘 확인<br>
                            • Referer 헤더 검증<br>
                            • SameSite 쿠키 설정 확인<br>
                            • 이중 제출 쿠키 패턴 검사
                        `;
                    }

                    detailsHTML += `
                        <div class="step3-detail-item step3-detail-success">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge success">✓ 안전</span>
                                <strong>${testTitle} 통과</strong>
                            </div>
                            <div class="step3-detail-desc">
                                다음 항목들을 검사하여 문제가 발견되지 않았습니다:<br>
                                ${checkedItems}
                            </div>
                        </div>
                    `;

                    // 추가 설정 정보가 있는 경우
                    if (testData.configuration) {
                        detailsHTML += `
                            <div class="step3-detail-item step3-detail-info">
                                <div class="step3-detail-header">
                                    <strong>현재 설정</strong>
                                </div>
                                <div class="step3-detail-desc">
                                    ${Object.entries(testData.configuration).map(([key, value]) =>
                                        `${key}: <code>${value}</code>`
                                    ).join('<br>')}
                                </div>
                            </div>
                        `;
                    }
                }

                detailsHTML += '</div>';
                detailsDiv.innerHTML = detailsHTML;
            }
            // 기타 이슈 상세 정보
            else if (testData && testData.issues && testData.issues.length > 0) {
                let detailsHTML = '<div class="step3-details-content">';

                testData.issues.forEach(issue => {
                    detailsHTML += `
                        <div class="step3-detail-item">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge ${issue.severity || 'medium'}">
                                    ${getSeverityLabel(issue.severity || 'medium')}
                                </span>
                                <strong>${issue.type || issue.name || '이슈'}</strong>
                            </div>
                            <div class="step3-detail-desc">${issue.description || issue.message || '설정 문제가 발견되었습니다.'}</div>
                            ${issue.recommendation ? `
                                <div class="step3-detail-recommendation">
                                    ${issue.recommendation}
                                </div>
                            ` : ''}
                        </div>
                    `;
                });

                detailsHTML += '</div>';
                detailsDiv.innerHTML = detailsHTML;
            }
            // SSL/TLS 상세 정보
            else if (test.id === 'ssl_tls' && testData) {
                let detailsHTML = '<div class="step3-details-content">';

                // SSL/TLS가 활성화된 경우
                if (testData.enabled !== false) {
                    detailsHTML += `
                        <div class="step3-detail-item step3-detail-success">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge success">✓ 안전</span>
                                <strong>SSL/TLS 보안 검사 통과</strong>
                            </div>
                            <div class="step3-detail-desc">
                                다음 보안 항목들이 확인되었습니다:<br>
                                • SSL/TLS 암호화 활성화 확인<br>
                                • 안전한 프로토콜 버전 사용 (TLS 1.2 이상)<br>
                                • 강력한 암호화 스위트 사용<br>
                                • 인증서 유효성 검증<br>
                                • HSTS 헤더 설정 확인
                            </div>
                        </div>
                    `;

                    if (testData.protocol) {
                        detailsHTML += `
                            <div class="step3-detail-item step3-detail-info">
                                <div class="step3-detail-header">
                                    <strong>연결 정보</strong>
                                </div>
                                <div class="step3-detail-desc">
                                    프로토콜: <code>${testData.protocol}</code><br>
                                    ${testData.cipher ? `암호화 스위트: <code>${testData.cipher}</code><br>` : ''}
                                    ${testData.key_exchange ? `키 교환: <code>${testData.key_exchange}</code><br>` : ''}
                                    ${testData.mac ? `MAC: <code>${testData.mac}</code>` : ''}
                                </div>
                            </div>
                        `;
                    }

                    if (testData.certificate) {
                        const cert = testData.certificate;
                        const now = new Date();
                        const expires = cert.expires ? new Date(cert.expires) : null;
                        const daysUntilExpiry = expires ? Math.floor((expires - now) / (1000 * 60 * 60 * 24)) : null;

                        detailsHTML += `
                            <div class="step3-detail-item">
                                <div class="step3-detail-header">
                                    <strong>인증서 정보</strong>
                                </div>
                                <div class="step3-detail-desc">
                                    ${cert.issuer ? `발급자: ${cert.issuer}<br>` : ''}
                                    ${cert.subject ? `주체: ${cert.subject}<br>` : ''}
                                    ${cert.san ? `대체 이름: ${cert.san}<br>` : ''}
                                    ${cert.expires ? `만료일: ${expires.toLocaleDateString('ko-KR')} (${daysUntilExpiry}일 남음)<br>` : ''}
                                    ${cert.signature_algorithm ? `서명 알고리즘: ${cert.signature_algorithm}` : ''}
                                </div>
                            </div>
                        `;
                    }
                } else {
                    // SSL/TLS가 비활성화된 경우
                    detailsHTML += `
                        <div class="step3-detail-item">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge high">경고</span>
                                <strong>SSL/TLS 미사용</strong>
                            </div>
                            <div class="step3-detail-desc">
                                이 사이트는 SSL/TLS 암호화를 사용하지 않습니다.
                            </div>
                            <div class="step3-detail-recommendation">
                                HTTPS를 활성화하여 데이터 전송을 암호화하세요.
                            </div>
                        </div>
                    `;
                }

                detailsHTML += '</div>';
                detailsDiv.innerHTML = detailsHTML;
            }

            item.appendChild(detailsDiv);
        }

        container.appendChild(item);
    });
}

/**
 * Display standards test details
 */
function displayStandardsDetails(result) {
    const container = document.getElementById('standardsTestList');
    container.innerHTML = '';

    // 동적 메타데이터 사용 (API에서 제공)
    const tests = result.scanner_metadata || [];

    // 메타데이터가 없는 경우 기본값 사용 (하위 호환성)
    if (tests.length === 0) {
        const defaultTests = [
            { name: 'SEO 검사', field: 'seo_issues', score_field: 'seo_score', icon: '🔍', id: 'seo' },
            { name: 'HTML 구조 검증', field: 'html_errors', count_field: 'html_error_count', icon: '📄', id: 'html' },
            { name: 'CSS 분석', field: 'css_errors', count_field: 'css_error_count', icon: '🎨', id: 'css' },
            { name: 'JavaScript 검사', field: 'js_errors', count_field: 'js_error_count', icon: '📜', id: 'javascript' }
        ];
        tests.push(...defaultTests);
    }

    tests.forEach(test => {
        const item = document.createElement('div');
        item.className = 'step3-test-item';

        let statusClass = 'pass';
        let badgeText = '통과';
        let hasDetails = false;

        // score_field와 count_field 처리 (동적 메타데이터)
        const scoreField = test.score_field || test.score;
        const countField = test.count_field || test.count;
        const testData = test.results || result[test.field];

        if (scoreField && result[scoreField] !== undefined) {
            const score = result[scoreField];
            if (score >= 80) {
                badgeText = `${score}점 (우수)`;
                statusClass = 'pass';
                hasDetails = true; // 통과한 경우에도 상세 정보 표시
            } else if (score >= 60) {
                badgeText = `${score}점 (양호)`;
                statusClass = 'warning';
                hasDetails = true;
            } else {
                badgeText = `${score}점 (개선필요)`;
                statusClass = 'fail';
                hasDetails = true;
            }
        } else if (countField && result[countField] !== undefined) {
            const count = result[countField];
            if (count === 0) {
                badgeText = '오류 없음';
                statusClass = 'pass';
                hasDetails = true; // 통과한 경우에도 상세 정보 표시
            } else if (count <= 5) {
                badgeText = `오류 ${count}개`;
                statusClass = 'warning';
                hasDetails = true;
            } else {
                badgeText = `오류 ${count}개`;
                statusClass = 'fail';
                hasDetails = true;
            }
        }

        // Create header with expandable functionality
        const headerHTML = `
            <div class="step3-test-header" ${hasDetails ? 'onclick="toggleDetails(this)"' : ''}>
                <div class="step3-test-status">${test.icon || '🔍'}</div>
                <div class="step3-test-name">
                    ${test.name || test.description || '테스트'}
                    ${hasDetails ? '<span class="step3-expand-icon">▼</span>' : ''}
                </div>
                <div class="step3-test-result">
                    <span class="step3-test-badge ${statusClass}">${badgeText}</span>
                </div>
            </div>
        `;

        item.innerHTML = headerHTML;

        // Add detailed information section
        if (hasDetails) {
            const detailsDiv = document.createElement('div');
            detailsDiv.className = 'step3-test-details';
            detailsDiv.style.display = 'none';

            let detailsHTML = '<div class="step3-details-content">';

            // SEO 이슈 상세 정보
            if (test.id === 'seo') {
                if (testData && testData.length > 0) {
                    testData.forEach(issue => {
                        detailsHTML += `
                            <div class="step3-detail-item">
                                <div class="step3-detail-header">
                                    <span class="step3-severity-badge ${issue.severity || 'medium'}">
                                        ${getSeverityLabel(issue.severity || 'medium')}
                                    </span>
                                    <strong>${issue.type || 'SEO 이슈'}</strong>
                                </div>
                                <div class="step3-detail-desc">${issue.description || issue.message || 'SEO 최적화가 필요합니다.'}</div>
                                ${issue.recommendation ? `
                                    <div class="step3-detail-recommendation">
                                        ${issue.recommendation}
                                    </div>
                                ` : ''}
                            </div>
                        `;
                    });
                } else {
                    // SEO 검사 통과
                    detailsHTML += `
                        <div class="step3-detail-item step3-detail-success">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge success">✓ 최적화됨</span>
                                <strong>SEO 검사 통과</strong>
                            </div>
                            <div class="step3-detail-desc">
                                다음 SEO 요소들이 올바르게 구성되어 있습니다:<br>
                                • 메타 타이틀 태그 설정<br>
                                • 메타 디스크립션 태그 설정<br>
                                • 적절한 제목 태그(H1-H6) 구조<br>
                                • Open Graph 메타 태그<br>
                                • 구조화된 데이터(Schema.org)<br>
                                • XML 사이트맵<br>
                                • robots.txt 파일<br>
                                • 이미지 alt 텍스트
                            </div>
                        </div>
                    `;
                }
            }
            // HTML 에러 상세 정보
            else if (test.id === 'html') {
                if (testData && testData.length > 0) {
                    testData.forEach(error => {
                        detailsHTML += `
                            <div class="step3-detail-item">
                                <div class="step3-detail-header">
                                    <span class="step3-severity-badge ${error.type === 'error' ? 'high' : 'medium'}">
                                        ${error.type === 'error' ? '오류' : '경고'}
                                    </span>
                                    <strong>HTML ${error.type || '이슈'}</strong>
                                </div>
                                ${error.line ? `<div class="step3-detail-location">위치: 라인 ${error.line}${error.column ? `, 컬럼 ${error.column}` : ''}</div>` : ''}
                                <div class="step3-detail-desc">${error.message || error.description || 'HTML 구조에 문제가 있습니다.'}</div>
                                ${error.extract ? `
                                    <div class="step3-detail-evidence">
                                        <code>${error.extract}</code>
                                    </div>
                                ` : ''}
                                <div class="step3-detail-recommendation">
                                    <strong>해결 방법:</strong><br>
                                    HTML 문법을 확인하고 올바른 태그 구조를 사용하세요.
                                </div>
                            </div>
                        `;
                    });
                } else {
                    // HTML 검증 통과
                    detailsHTML += `
                        <div class="step3-detail-item step3-detail-success">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge success">✓ 유효함</span>
                                <strong>HTML 구조 검증 통과</strong>
                            </div>
                            <div class="step3-detail-desc">
                                다음 HTML 표준 항목들이 검증되었습니다:<br>
                                • DOCTYPE 선언 확인<br>
                                • HTML5 표준 준수<br>
                                • 올바른 태그 중첩 구조<br>
                                • 필수 속성 존재 여부<br>
                                • 중복 ID 검사<br>
                                • 비표준 태그 사용 검사<br>
                                • 문자 인코딩 선언<br>
                                • 시맨틱 태그 사용
                            </div>
                        </div>
                    `;
                }
            }
            // CSS 에러 상세 정보
            else if (test.id === 'css') {
                if (testData && testData.length > 0) {
                    testData.forEach(error => {
                        detailsHTML += `
                            <div class="step3-detail-item">
                                <div class="step3-detail-header">
                                    <span class="step3-severity-badge ${error.type === 'error' ? 'high' : 'medium'}">
                                        ${error.type === 'error' ? '오류' : '경고'}
                                    </span>
                                    <strong>CSS ${error.type || '이슈'}</strong>
                                </div>
                                ${error.line ? `<div class="step3-detail-location">위치: 라인 ${error.line}</div>` : ''}
                                <div class="step3-detail-desc">${error.message || error.description || 'CSS 스타일에 문제가 있습니다.'}</div>
                                ${error.context ? `
                                    <div class="step3-detail-evidence">
                                        <code>${error.context}</code>
                                    </div>
                                ` : ''}
                                <div class="step3-detail-recommendation">
                                    <strong>해결 방법:</strong><br>
                                    CSS 속성과 값이 올바른지 확인하세요.
                                </div>
                            </div>
                        `;
                    });
                } else {
                    // CSS 검증 통과
                    detailsHTML += `
                        <div class="step3-detail-item step3-detail-success">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge success">✓ 유효함</span>
                                <strong>CSS 분석 통과</strong>
                            </div>
                            <div class="step3-detail-desc">
                                다음 CSS 품질 항목들이 검증되었습니다:<br>
                                • CSS3 문법 준수<br>
                                • 유효한 속성과 값 사용<br>
                                • 벤더 프리픽스 적절한 사용<br>
                                • 중복 규칙 검사<br>
                                • 사용되지 않는 선택자 검사<br>
                                • 미디어 쿼리 구조<br>
                                • CSS 성능 최적화<br>
                                • 브라우저 호환성
                            </div>
                        </div>
                    `;
                }
            }
            // JavaScript 에러 상세 정보
            else if (test.id === 'javascript') {
                if (testData && testData.length > 0) {
                    testData.forEach(error => {
                        detailsHTML += `
                            <div class="step3-detail-item">
                                <div class="step3-detail-header">
                                    <span class="step3-severity-badge high">오류</span>
                                    <strong>${error.name || 'JavaScript 오류'}</strong>
                                </div>
                                ${error.source ? `<div class="step3-detail-location">소스: ${error.source}</div>` : ''}
                                ${error.line ? `<div class="step3-detail-location">위치: 라인 ${error.line}${error.column ? `, 컬럼 ${error.column}` : ''}</div>` : ''}
                                <div class="step3-detail-desc">${error.message || error.description || 'JavaScript 실행 중 오류가 발생했습니다.'}</div>
                                ${error.stack ? `
                                    <div class="step3-detail-evidence">
                                        <pre><code>${error.stack}</code></pre>
                                    </div>
                                ` : ''}
                                <div class="step3-detail-recommendation">
                                    <strong>해결 방법:</strong><br>
                                    JavaScript 코드를 검토하고 오류를 수정하세요.
                                </div>
                            </div>
                        `;
                    });
                } else {
                    // JavaScript 검사 통과
                    detailsHTML += `
                        <div class="step3-detail-item step3-detail-success">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge success">✓ 정상</span>
                                <strong>JavaScript 검사 통과</strong>
                            </div>
                            <div class="step3-detail-desc">
                                다음 JavaScript 품질 항목들이 검증되었습니다:<br>
                                • 구문 오류 없음<br>
                                • 런타임 오류 없음<br>
                                • 콘솔 오류 없음<br>
                                • 적절한 에러 핸들링<br>
                                • 메모리 누수 검사<br>
                                • 성능 최적화 확인<br>
                                • 비동기 처리 정상<br>
                                • 브라우저 호환성 확인
                            </div>
                        </div>
                    `;
                }
            }
            // 일반 오류 처리
            else if (testData.length > 0) {
                testData.forEach(error => {
                    detailsHTML += `
                        <div class="step3-detail-item">
                            <div class="step3-detail-header">
                                <strong>${error.type || '이슈'}</strong>
                            </div>
                            <div class="step3-detail-desc">${error.message || error.description || '문제가 발견되었습니다.'}</div>
                        </div>
                    `;
                });
            }

            // 메타 태그 정보 표시 (SEO인 경우)
            if (test.id === 'seo' && result.meta_tags) {
                detailsHTML += `
                    <div class="step3-detail-item step3-detail-info">
                        <div class="step3-detail-header">
                            <strong>메타 태그 정보</strong>
                        </div>
                        <div class="step3-detail-desc">
                            ${result.meta_tags.title ? `<div>Title: ${result.meta_tags.title}</div>` : '<div>⚠️ Title 태그 누락</div>'}
                            ${result.meta_tags.description ? `<div>Description: ${result.meta_tags.description}</div>` : '<div>⚠️ Description 메타 태그 누락</div>'}
                            ${result.meta_tags.keywords ? `<div>Keywords: ${result.meta_tags.keywords}</div>` : ''}
                        </div>
                    </div>
                `;
            }

            detailsHTML += '</div>';
            detailsDiv.innerHTML = detailsHTML;
            item.appendChild(detailsDiv);
        }

        container.appendChild(item);
    });
}

/**
 * Display accessibility test details
 */
function displayAccessibilityDetails(result) {
    const container = document.getElementById('accessibilityTestList');
    container.innerHTML = '';

    // 동적 메타데이터 사용 (API에서 제공)
    const tests = result.scanner_metadata || [];

    // 메타데이터가 없는 경우 기본값 사용 (하위 호환성)
    if (tests.length === 0) {
        const defaultTests = [
            { name: '대체 텍스트 검사', field: 'alt_text_missing', icon: '🖼️', id: 'alt_text' },
            { name: '폼 레이블 검사', field: 'form_labels', icon: '📋', id: 'form_labels' },
            { name: '제목 구조 검사', field: 'heading_structure', icon: '📑', id: 'heading' },
            { name: 'ARIA 속성 검사', field: 'aria_attributes', icon: '♿', id: 'aria' },
            { name: '색상 대비 검사', field: 'color_contrast', icon: '🎨', id: 'contrast' },
            { name: '키보드 접근성', field: 'keyboard_navigation', icon: '⌨️', id: 'keyboard' },
            { name: '스크린리더 호환성', field: 'screen_reader', icon: '🔊', id: 'screen_reader' }
        ];
        tests.push(...defaultTests);
    }

    tests.forEach(test => {
        // 메타데이터에서 결과 가져오기
        const testData = test.results || result[test.field];
        const item = document.createElement('div');
        item.className = 'step3-test-item';

        let statusClass = 'pass';
        let badgeText = '통과';
        let hasDetails = false;

        if (testData && Array.isArray(testData) && testData.length > 0) {
            statusClass = 'warning';
            badgeText = `이슈 ${testData.length}개`;
            hasDetails = true;
        } else if (testData === false) {
            statusClass = 'fail';
            badgeText = '실패';
            hasDetails = true;
        } else if (!testData) {
            statusClass = 'info';
            badgeText = '미검사';
        } else {
            // 통과한 경우에도 상세 정보 표시
            hasDetails = true;
        }

        // Create header with expandable functionality
        const headerHTML = `
            <div class="step3-test-header" ${hasDetails ? 'onclick="toggleDetails(this)"' : ''}>
                <div class="step3-test-status">${test.icon || '🔍'}</div>
                <div class="step3-test-name">
                    ${test.name || test.description || '테스트'}
                    ${hasDetails ? '<span class="step3-expand-icon">▼</span>' : ''}
                </div>
                <div class="step3-test-result">
                    <span class="step3-test-badge ${statusClass}">${badgeText}</span>
                </div>
            </div>
        `;

        item.innerHTML = headerHTML;

        // Add detailed information section
        if (hasDetails) {
            const detailsDiv = document.createElement('div');
            detailsDiv.className = 'step3-test-details';
            detailsDiv.style.display = 'none';

            let detailsHTML = '<div class="step3-details-content">';

            if (testData && Array.isArray(testData) && testData.length > 0) {
                // 이슈가 있는 경우
                testData.forEach(issue => {
                    const severity = issue.impact || issue.severity || 'medium';
                    const wcagLevel = issue.wcag || '';

                    detailsHTML += `
                        <div class="step3-detail-item">
                            <div class="step3-detail-header">
                                <span class="step3-severity-badge ${severity}">
                                    ${getSeverityLabel(severity)}
                                </span>
                                ${wcagLevel ? `<span class="step3-wcag-badge">WCAG ${wcagLevel}</span>` : ''}
                                <strong>${issue.type || test.name}</strong>
                            </div>
                            ${issue.element ? `<div class="step3-detail-location">요소: <code>${issue.element}</code></div>` : ''}
                            ${issue.selector ? `<div class="step3-detail-location">위치: <code>${issue.selector}</code></div>` : ''}
                            <div class="step3-detail-desc">${issue.description || issue.message || '접근성 지침을 위반했습니다.'}</div>
                            <div class="step3-detail-recommendation">
                                <strong>해결 방법:</strong><br>
                                ${getAccessibilityRecommendation(test.id, issue)}
                            </div>
                        </div>
                    `;
                });
            } else {
                // 테스트 통과한 경우
                let testTitle = test.name || test.description || '접근성 테스트';
                let checkedItems = '';

                if (test.id === 'alt_text') {
                    checkedItems = `
                        • 모든 이미지에 대체 텍스트 존재<br>
                        • 장식용 이미지는 빈 alt 속성 사용<br>
                        • 의미 있는 대체 텍스트 제공<br>
                        • 중복된 설명 없음
                    `;
                } else if (test.id === 'form_labels') {
                    checkedItems = `
                        • 모든 폼 요소에 레이블 연결<br>
                        • 명확한 레이블 텍스트 사용<br>
                        • 필수 필드 표시<br>
                        • 오류 메시지 접근 가능
                    `;
                } else if (test.id === 'heading') {
                    checkedItems = `
                        • 논리적인 제목 구조<br>
                        • H1-H6 순서 준수<br>
                        • 제목 레벨 건너뛰기 없음<br>
                        • 의미 있는 제목 사용
                    `;
                } else if (test.id === 'aria') {
                    checkedItems = `
                        • ARIA 속성 올바른 사용<br>
                        • role 속성 적절히 적용<br>
                        • aria-label 및 aria-labelledby 검증<br>
                        • 동적 콘텐츠 접근성 확보
                    `;
                } else if (test.id === 'contrast') {
                    checkedItems = `
                        • 텍스트 색상 대비 4.5:1 이상<br>
                        • 큰 텍스트 색상 대비 3:1 이상<br>
                        • UI 구성요소 대비 3:1 이상<br>
                        • 그래픽 객체 대비 충족
                    `;
                } else if (test.id === 'keyboard') {
                    checkedItems = `
                        • 모든 기능 키보드로 접근 가능<br>
                        • Tab 순서 논리적 구성<br>
                        • 포커스 표시 명확<br>
                        • 키보드 트랩 없음
                    `;
                } else if (test.id === 'screen_reader') {
                    checkedItems = `
                        • 스크린리더 호환성 확인<br>
                        • 의미 있는 텍스트 대체<br>
                        • 랜드마크 역할 적절히 사용<br>
                        • 동적 변경사항 알림
                    `;
                } else {
                    checkedItems = `
                        • 접근성 기준 충족<br>
                        • WCAG 2.1 가이드라인 준수<br>
                        • 보조 기술 호환성 확인<br>
                        • 사용자 경험 최적화
                    `;
                }

                detailsHTML += `
                    <div class="step3-detail-item step3-detail-success">
                        <div class="step3-detail-header">
                            <span class="step3-severity-badge success">✓ 준수</span>
                            <strong>${testTitle} 통과</strong>
                        </div>
                        <div class="step3-detail-desc">
                            다음 접근성 항목들이 검증되었습니다:<br>
                            ${checkedItems}
                        </div>
                    </div>
                `;
            }

            detailsHTML += '</div>';
            detailsDiv.innerHTML = detailsHTML;
            item.appendChild(detailsDiv);
        }

        container.appendChild(item);
    });

    // Display WCAG level if available
    if (result.wcag_level) {
        const wcagInfo = document.createElement('div');
        wcagInfo.style.marginTop = '1rem';
        wcagInfo.style.padding = '0.75rem';
        wcagInfo.style.background = '#f1f5f9';
        wcagInfo.style.borderRadius = '8px';
        wcagInfo.innerHTML = `<strong>WCAG 준수 수준:</strong> ${result.wcag_level}`;
        container.appendChild(wcagInfo);
    }
}

/**
 * Display summary
 */
function displaySummary(data) {
    document.getElementById('resultUrl').textContent = data.url;
    document.getElementById('resultTime').textContent = formatDateTimeKST(data.completed_at);
    document.getElementById('resultDuration').textContent = data.duration || 'N/A';
}

/**
 * Display security results
 */
function displaySecurityResults(securityData) {
    // Chart.js removed - display security details only

    // Display security headers
    const detailsSection = document.getElementById('securityDetails');
    let html = '<h3>보안 헤더</h3><div class="headers-list">';

    if (securityData.security_headers) {
        for (const [header, info] of Object.entries(securityData.security_headers)) {
            html += `
                <div class="header-item">
                    <span class="header-name">${header}</span>
                    <div class="header-status">
                        <div class="status-icon ${info.present ? 'present' : 'missing'}"></div>
                        <span>${info.present ? '설정됨' : '미설정'}</span>
                    </div>
                </div>
            `;
        }
    }

    html += '</div>';

    // SSL/TLS
    if (securityData.ssl_tls_result) {
        html += `
            <h3 class="mt-3">SSL/TLS</h3>
            <div class="detail-item">
                <div class="detail-description">${securityData.ssl_tls_result.message || ''}</div>
            </div>
        `;
    }

    detailsSection.innerHTML = html;
}

/**
 * Display standards results
 */
function displayStandardsResults(standardsData) {
    // Chart.js removed - display standards details only

    // Display SEO details
    const detailsSection = document.getElementById('standardsDetails');
    let html = '<h3>SEO</h3>';

    html += `
        <div class="detail-item">
            <div class="detail-header">
                <span class="detail-title">SEO 점수</span>
                <span class="badge ${getScoreBadgeClass(standardsData.seo_score)}">${standardsData.seo_score}</span>
            </div>
        </div>
    `;

    if (standardsData.seo_issues && standardsData.seo_issues.length > 0) {
        html += '<h4 class="mt-2">SEO 이슈</h4><div class="seo-issues">';
        standardsData.seo_issues.forEach(issue => {
            html += `
                <div class="seo-issue ${issue.severity}">
                    <div class="seo-issue-message">${issue.message}</div>
                </div>
            `;
        });
        html += '</div>';
    }

    // Meta tags
    if (standardsData.meta_tags) {
        html += '<h4 class="mt-2">메타 태그</h4>';
        for (const [key, value] of Object.entries(standardsData.meta_tags)) {
            html += `
                <div class="detail-item">
                    <div class="detail-title">${key}</div>
                    <div class="detail-description">${value}</div>
                </div>
            `;
        }
    }

    // Performance
    html += '<h4 class="mt-2">성능</h4>';
    html += `
        <div class="detail-item">
            <div class="detail-title">페이지 로드 시간</div>
            <div class="detail-description">${standardsData.page_load_time ? standardsData.page_load_time.toFixed(2) + 's' : 'N/A'}</div>
        </div>
        <div class="detail-item">
            <div class="detail-title">페이지 크기</div>
            <div class="detail-description">${standardsData.page_size ? formatBytes(standardsData.page_size) : 'N/A'}</div>
        </div>
    `;

    detailsSection.innerHTML = html;
}

/**
 * Display accessibility results
 */
function displayAccessibilityResults(accessibilityData) {
    // Chart.js removed - display accessibility details only

    // Display accessibility details
    const detailsSection = document.getElementById('accessibilityDetails');
    let html = '<h3>접근성 이슈</h3>';

    html += `
        <div class="detail-item">
            <div class="detail-header">
                <span class="detail-title">총 이슈</span>
                <span class="badge badge-info">${accessibilityData.total_issues || 0}</span>
            </div>
        </div>
        <div class="detail-item">
            <div class="detail-header">
                <span class="detail-title">심각한 이슈</span>
                <span class="badge badge-danger">${accessibilityData.critical_issues || 0}</span>
            </div>
        </div>
    `;

    // Alt text issues
    if (accessibilityData.alt_text_missing && accessibilityData.alt_text_missing.length > 0) {
        html += `<h4 class="mt-2">누락된 Alt 텍스트 (${accessibilityData.alt_text_missing.length}개)</h4>`;
        accessibilityData.alt_text_missing.slice(0, 5).forEach(issue => {
            html += `
                <div class="detail-item">
                    <div class="detail-description">${issue.message}</div>
                    <div class="vulnerability-affected">이미지: ${issue.src}</div>
                </div>
            `;
        });
        if (accessibilityData.alt_text_missing.length > 5) {
            html += `<p class="text-muted text-center">그 외 ${accessibilityData.alt_text_missing.length - 5}개 더...</p>`;
        }
    }

    // Form label issues
    if (accessibilityData.form_labels && accessibilityData.form_labels.length > 0) {
        html += `<h4 class="mt-2">누락된 폼 레이블 (${accessibilityData.form_labels.length}개)</h4>`;
        accessibilityData.form_labels.slice(0, 5).forEach(issue => {
            html += `
                <div class="detail-item">
                    <div class="detail-description">${issue.message}</div>
                </div>
            `;
        });
    }

    detailsSection.innerHTML = html;
}

/**
 * Display vulnerabilities
 */
function displayVulnerabilities(vulnerabilities) {
    const container = document.getElementById('vulnerabilitiesList');
    container.innerHTML = '';

    if (!vulnerabilities || vulnerabilities.length === 0) {
        container.innerHTML = '<div class="step3-vuln-item"><span class="step3-vuln-text">발견된 취약점이 없습니다. 안전합니다!</span></div>';
        return;
    }

    // Group by severity
    const grouped = {
        critical: [],
        high: [],
        medium: [],
        low: []
    };

    vulnerabilities.forEach(vuln => {
        const severity = vuln.severity.toLowerCase();
        if (grouped[severity]) {
            grouped[severity].push(vuln);
        }
    });

    // Display by severity (max 10 items total)
    let displayCount = 0;
    const maxDisplay = 10;

    ['critical', 'high', 'medium', 'low'].forEach(severity => {
        if (displayCount >= maxDisplay) return;

        grouped[severity].slice(0, maxDisplay - displayCount).forEach(vuln => {
            const item = document.createElement('div');
            item.className = 'step3-vuln-item';
            item.innerHTML = `
                <span class="step3-vuln-severity ${severity}">${getSeverityLabel(severity)}</span>
                <span class="step3-vuln-text">${escapeHtml(vuln.title || vuln.vulnerability_type)}</span>
            `;
            container.appendChild(item);
            displayCount++;
        });
    });

    // Show total count if more than displayed
    const totalCount = vulnerabilities.length;
    if (totalCount > maxDisplay) {
        const moreItem = document.createElement('div');
        moreItem.className = 'step3-vuln-item';
        moreItem.innerHTML = `
            <span class="step3-vuln-text" style="text-align: center; width: 100%; color: #94a3b8;">
                ... 그 외 ${totalCount - maxDisplay}개 이슈
            </span>
        `;
        container.appendChild(moreItem);
    }
}

/**
 * Switch tabs
 */
function switchTab(tabName) {
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
        }
    });

    // Update panes
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
    });
    document.getElementById(`${tabName}Tab`).classList.add('active');
}

/**
 * Reset to scan form (Step 1)
 */
function resetToScanForm() {
    console.log('Resetting to Step 1');

    // Clear scan ID
    currentScanId = null;

    // Clear interval
    if (statusPollInterval) {
        clearInterval(statusPollInterval);
    }

    // Reset form
    document.getElementById('scanForm').reset();

    // Hide all steps first
    document.querySelectorAll('.wizard-step').forEach(step => {
        step.classList.remove('active');
        step.style.display = 'none';
    });

    // Show step 1
    const step1 = document.getElementById('step1');
    if (step1) {
        step1.classList.add('active');
        step1.style.display = 'block';
        console.log('Step 1 is now visible');
    }

    // Re-enable button
    const scanBtn = document.getElementById('scanBtn');
    scanBtn.disabled = false;
    scanBtn.textContent = '스캔 시작';
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Format datetime to KST
 */
function formatDateTimeKST(utcDateString) {
    if (!utcDateString) return 'N/A';

    const date = new Date(utcDateString);

    // Convert to KST (UTC+9)
    const kstDate = new Date(date.getTime() + (9 * 60 * 60 * 1000));

    const year = kstDate.getUTCFullYear();
    const month = String(kstDate.getUTCMonth() + 1).padStart(2, '0');
    const day = String(kstDate.getUTCDate()).padStart(2, '0');
    const hours = String(kstDate.getUTCHours()).padStart(2, '0');
    const minutes = String(kstDate.getUTCMinutes()).padStart(2, '0');
    const seconds = String(kstDate.getUTCSeconds()).padStart(2, '0');

    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} KST`;
}

/**
 * Get risk color
 */
function getRiskColor(riskLevel) {
    const colors = {
        'low': '#22c55e',
        'medium': '#f59e0b',
        'high': '#f97316',
        'critical': '#ef4444'
    };
    return colors[riskLevel] || '#64748b';
}

/**
 * Get score color
 */
function getScoreColor(score) {
    if (score >= 80) return '#22c55e';
    if (score >= 60) return '#f59e0b';
    if (score >= 40) return '#f97316';
    return '#ef4444';
}

/**
 * Get score badge class
 */
function getScoreBadgeClass(score) {
    if (score >= 80) return 'badge-success';
    if (score >= 60) return 'badge-warning';
    return 'badge-danger';
}

/**
 * Format bytes
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
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
 * Get severity label in Korean
 */
function getSeverityLabel(severity) {
    const labels = {
        'critical': '치명적',
        'high': '높음',
        'medium': '중간',
        'low': '낮음'
    };
    return labels[severity.toLowerCase()] || severity;
}

// ============================================================================
// Wizard Functions
// ============================================================================

/**
 * Go to specific wizard step
 */
function goToStep(stepNumber) {
    console.log(`Going to step ${stepNumber}`);

    // Hide all steps first
    document.querySelectorAll('.wizard-step').forEach(step => {
        step.classList.remove('active');
        step.style.display = 'none';
    });

    // Show target step
    const targetStep = document.getElementById(`step${stepNumber}`);
    if (targetStep) {
        targetStep.classList.add('active');
        targetStep.style.display = 'block';
        console.log(`Step ${stepNumber} is now visible`);
    } else {
        console.error(`Step ${stepNumber} element not found!`);
    }
}

/**
 * Reset loading display
 */
function resetLoadingSteps() {
    const stepIcon = document.getElementById('stepIcon');
    const stepTitle = document.getElementById('stepTitle');
    const stepDesc = document.getElementById('stepDesc');

    stepIcon.textContent = '🔍';
    stepTitle.textContent = '초기화';
    stepDesc.textContent = '스캔 준비 중...';
}

/**
 * Update loading steps based on progress
 */
function updateLoadingSteps(progress) {
    // Define progress ranges for each step
    const steps = [
        { start: 0, end: 20, icon: '🔍', title: '초기화', desc: '스캔 준비 중...' },
        { start: 20, end: 50, icon: '🔒', title: '보안 검사', desc: 'OWASP Top 10, XSS, SQL Injection 등' },
        { start: 50, end: 75, icon: '📊', title: '웹 표준 검사', desc: 'HTML, CSS, SEO 검증' },
        { start: 75, end: 95, icon: '♿', title: '접근성 검사', desc: 'WCAG 2.1 가이드라인 검증' },
        { start: 95, end: 100, icon: '✅', title: '완료', desc: '결과 생성 중...' }
    ];

    // Find current step
    let currentStep = steps[0];
    for (const step of steps) {
        if (progress >= step.start && progress < step.end) {
            currentStep = step;
            break;
        } else if (progress >= step.end) {
            currentStep = step;
        }
    }

    // Update display
    const stepIcon = document.getElementById('stepIcon');
    const stepTitle = document.getElementById('stepTitle');
    const stepDesc = document.getElementById('stepDesc');

    if (stepIcon && stepTitle && stepDesc) {
        stepIcon.textContent = currentStep.icon;
        stepTitle.textContent = currentStep.title;
        stepDesc.textContent = currentStep.desc;
    }
}

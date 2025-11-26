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
            { name: '보안 헤더 검사', field: 'security_headers', icon: '🛡️' },
            { name: 'SSL/TLS 검사', field: 'ssl_tls_result', icon: '🔐' },
            { name: 'XSS 취약점 스캔', field: 'xss_vulnerabilities', icon: '⚠️' },
            { name: 'SQL Injection 스캔', field: 'sql_injection', icon: '💉' },
            { name: 'CORS 설정 검사', field: 'cors_misconfiguration', icon: '🌐' },
            { name: '쿠키 보안 검사', field: 'sensitive_data_exposure', icon: '🍪' },
            { name: 'CSRF 보호 검사', field: 'csrf_protection', icon: '🔒' },
            { name: '클릭재킹 방어 검사', field: 'clickjacking', icon: '🖱️' },
            { name: '정보 노출 검사', field: 'insufficient_logging', icon: '📝' },
            { name: 'HTTP 메서드 검사', field: 'http_methods', icon: '📡' },
            { name: '민감한 파일 노출 검사', field: 'sensitive_files', icon: '📁' },
            { name: 'Mixed Content 검사', field: 'mixed_content', icon: '🔗' },
            { name: 'SRI 검사', field: 'sri_check', icon: '✓' },
            { name: '디렉토리 리스팅 검사', field: 'directory_listing', icon: '📂' },
            { name: 'Open Redirect 검사', field: 'open_redirects', icon: '↗️' }
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
        let issues = [];

        // Analyze test results
        if (testData) {
            if (testData.has_xss || testData.has_sqli) {
                status = '✗';
                statusClass = 'fail';
                badgeText = `취약점 ${testData.total || 0}개`;
                if (testData.vulnerabilities) {
                    issues = testData.vulnerabilities.slice(0, 3);
                }
            } else if (testData.misconfigured === true) {
                status = '⚠️';
                statusClass = 'warning';
                badgeText = '설정 오류';
                if (testData.issues) {
                    issues = testData.issues.slice(0, 3);
                }
            } else if (testData.missing_count > 0) {
                status = '⚠️';
                statusClass = 'warning';
                badgeText = `누락 ${testData.missing_count}개`;
            } else if (testData.status === 'warning') {
                status = '⚠️';
                statusClass = 'warning';
                badgeText = '경고';
            } else if (testData.status === 'ok' || testData.https === true) {
                status = '✓';
                statusClass = 'pass';
                badgeText = '통과';
            } else if (testData.issues && testData.issues.length > 0) {
                status = '⚠️';
                statusClass = 'warning';
                badgeText = `이슈 ${testData.issues.length}개`;
                issues = testData.issues.slice(0, 3);
            }
        }

        item.innerHTML = `
            <div class="step3-test-status">${test.icon || '🔍'}</div>
            <div class="step3-test-name">${test.name || test.description || '테스트'}</div>
            <div class="step3-test-result">
                <span class="step3-test-badge ${statusClass}">${badgeText}</span>
            </div>
        `;

        container.appendChild(item);

        // Add issues if any
        if (issues.length > 0) {
            const issuesList = document.createElement('div');
            issuesList.className = 'step3-test-issues';
            issues.forEach(issue => {
                const issueItem = document.createElement('div');
                issueItem.className = 'step3-test-issue-item';
                issueItem.textContent = `• ${issue.type || issue.description || issue.message || '이슈 발견'}`;
                issuesList.appendChild(issueItem);
            });
            container.appendChild(issuesList);
        }
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
            { name: 'SEO 검사', field: 'seo_issues', score_field: 'seo_score', icon: '🔍' },
            { name: 'HTML 구조 검증', field: 'html_errors', count_field: 'html_error_count', icon: '📄' },
            { name: 'CSS 분석', field: 'css_errors', count_field: 'css_error_count', icon: '🎨' },
            { name: 'JavaScript 검사', field: 'js_errors', count_field: 'js_error_count', icon: '📜' }
        ];
        tests.push(...defaultTests);
    }

    tests.forEach(test => {
        const item = document.createElement('div');
        item.className = 'step3-test-item';

        let statusClass = 'pass';
        let badgeText = '통과';

        // score_field와 count_field 처리 (동적 메타데이터)
        const scoreField = test.score_field || test.score;
        const countField = test.count_field || test.count;

        if (scoreField && result[scoreField] !== undefined) {
            const score = result[scoreField];
            if (score >= 80) {
                badgeText = `${score}점 (우수)`;
                statusClass = 'pass';
            } else if (score >= 60) {
                badgeText = `${score}점 (양호)`;
                statusClass = 'warning';
            } else {
                badgeText = `${score}점 (개선필요)`;
                statusClass = 'fail';
            }
        } else if (countField && result[countField] !== undefined) {
            const count = result[countField];
            if (count === 0) {
                badgeText = '오류 없음';
                statusClass = 'pass';
            } else if (count <= 5) {
                badgeText = `오류 ${count}개`;
                statusClass = 'warning';
            } else {
                badgeText = `오류 ${count}개`;
                statusClass = 'fail';
            }
        }

        item.innerHTML = `
            <div class="step3-test-status">${test.icon || '🔍'}</div>
            <div class="step3-test-name">${test.name || test.description || '테스트'}</div>
            <div class="step3-test-result">
                <span class="step3-test-badge ${statusClass}">${badgeText}</span>
            </div>
        `;

        container.appendChild(item);

        // Add error details if any
        const errors = result[test.field];
        if (errors && errors.length > 0) {
            const issuesList = document.createElement('div');
            issuesList.className = 'step3-test-issues';
            errors.slice(0, 3).forEach(error => {
                const issueItem = document.createElement('div');
                issueItem.className = 'step3-test-issue-item';
                issueItem.textContent = `• ${error.message || error.description || error.type || '오류 발견'}`;
                issuesList.appendChild(issueItem);
            });
            if (errors.length > 3) {
                const moreItem = document.createElement('div');
                moreItem.className = 'step3-test-issue-item';
                moreItem.textContent = `... 외 ${errors.length - 3}개 추가 오류`;
                issuesList.appendChild(moreItem);
            }
            container.appendChild(issuesList);
        }
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
            { name: '대체 텍스트 검사', field: 'alt_text_missing', icon: '🖼️' },
            { name: '폼 레이블 검사', field: 'form_labels', icon: '📋' },
            { name: '제목 구조 검사', field: 'heading_structure', icon: '📑' },
            { name: 'ARIA 속성 검사', field: 'aria_attributes', icon: '♿' },
            { name: '색상 대비 검사', field: 'color_contrast', icon: '🎨' },
            { name: '키보드 접근성', field: 'keyboard_navigation', icon: '⌨️' },
            { name: '스크린리더 호환성', field: 'screen_reader', icon: '🔊' }
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

        if (testData && Array.isArray(testData) && testData.length > 0) {
            statusClass = 'warning';
            badgeText = `이슈 ${testData.length}개`;
        } else if (testData === false) {
            statusClass = 'fail';
            badgeText = '실패';
        } else if (!testData) {
            statusClass = 'info';
            badgeText = '미검사';
        }

        item.innerHTML = `
            <div class="step3-test-status">${test.icon || '🔍'}</div>
            <div class="step3-test-name">${test.name || test.description || '테스트'}</div>
            <div class="step3-test-result">
                <span class="step3-test-badge ${statusClass}">${badgeText}</span>
            </div>
        `;

        container.appendChild(item);

        // Add issues if any
        if (testData && Array.isArray(testData) && testData.length > 0) {
            const issuesList = document.createElement('div');
            issuesList.className = 'step3-test-issues';
            testData.slice(0, 3).forEach(issue => {
                const issueItem = document.createElement('div');
                issueItem.className = 'step3-test-issue-item';
                issueItem.textContent = `• ${issue.element || issue.description || '접근성 이슈'}`;
                issuesList.appendChild(issueItem);
            });
            if (testData.length > 3) {
                const moreItem = document.createElement('div');
                moreItem.className = 'step3-test-issue-item';
                moreItem.textContent = `... 외 ${testData.length - 3}개 추가 이슈`;
                issuesList.appendChild(moreItem);
            }
            container.appendChild(issuesList);
        }
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
    // Create chart
    const ctx = document.getElementById('securityChart').getContext('2d');

    if (charts.security) {
        charts.security.destroy();
    }

    charts.security = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['점수', '남은 점수'],
            datasets: [{
                data: [securityData.overall_score, 100 - securityData.overall_score],
                backgroundColor: [
                    getRiskColor(securityData.risk_level),
                    '#e5e7eb'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            },
            cutout: '75%'
        },
        plugins: [{
            id: 'centerText',
            beforeDraw: function(chart) {
                const width = chart.width;
                const height = chart.height;
                const ctx = chart.ctx;
                ctx.restore();

                const fontSize = (height / 114).toFixed(2);
                ctx.font = `bold ${fontSize}em sans-serif`;
                ctx.textBaseline = 'middle';

                const text = `${securityData.overall_score}`;
                const textX = Math.round((width - ctx.measureText(text).width) / 2);
                const textY = height / 2;

                ctx.fillStyle = '#0f172a';
                ctx.fillText(text, textX, textY);

                ctx.font = `${fontSize * 0.4}em sans-serif`;
                const subText = securityData.risk_level.toUpperCase();
                const subTextX = Math.round((width - ctx.measureText(subText).width) / 2);
                const subTextY = height / 2 + 25;

                ctx.fillStyle = getRiskColor(securityData.risk_level);
                ctx.fillText(subText, subTextX, subTextY);

                ctx.save();
            }
        }]
    });

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
    // Create chart
    const ctx = document.getElementById('standardsChart').getContext('2d');

    if (charts.standards) {
        charts.standards.destroy();
    }

    charts.standards = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['점수', '남은 점수'],
            datasets: [{
                data: [standardsData.overall_score, 100 - standardsData.overall_score],
                backgroundColor: [
                    getScoreColor(standardsData.overall_score),
                    '#e5e7eb'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            },
            cutout: '75%'
        },
        plugins: [{
            id: 'centerText',
            beforeDraw: function(chart) {
                const width = chart.width;
                const height = chart.height;
                const ctx = chart.ctx;
                ctx.restore();

                const fontSize = (height / 114).toFixed(2);
                ctx.font = `bold ${fontSize}em sans-serif`;
                ctx.textBaseline = 'middle';

                const text = `${standardsData.overall_score}`;
                const textX = Math.round((width - ctx.measureText(text).width) / 2);
                const textY = height / 2;

                ctx.fillStyle = '#0f172a';
                ctx.fillText(text, textX, textY);

                ctx.save();
            }
        }]
    });

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
    // Create chart
    const ctx = document.getElementById('accessibilityChart').getContext('2d');

    if (charts.accessibility) {
        charts.accessibility.destroy();
    }

    charts.accessibility = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['점수', '남은 점수'],
            datasets: [{
                data: [accessibilityData.overall_score, 100 - accessibilityData.overall_score],
                backgroundColor: [
                    getScoreColor(accessibilityData.overall_score),
                    '#e5e7eb'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            },
            cutout: '75%'
        },
        plugins: [{
            id: 'centerText',
            beforeDraw: function(chart) {
                const width = chart.width;
                const height = chart.height;
                const ctx = chart.ctx;
                ctx.restore();

                const fontSize = (height / 114).toFixed(2);
                ctx.font = `bold ${fontSize}em sans-serif`;
                ctx.textBaseline = 'middle';

                const text = `${accessibilityData.overall_score}`;
                const textX = Math.round((width - ctx.measureText(text).width) / 2);
                const textY = height / 2;

                ctx.fillStyle = '#0f172a';
                ctx.fillText(text, textX, textY);

                ctx.font = `${fontSize * 0.4}em sans-serif`;
                const subText = `WCAG ${accessibilityData.wcag_level}`;
                const subTextX = Math.round((width - ctx.measureText(subText).width) / 2);
                const subTextY = height / 2 + 25;

                ctx.fillStyle = '#64748b';
                ctx.fillText(subText, subTextX, subTextY);

                ctx.save();
            }
        }]
    });

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

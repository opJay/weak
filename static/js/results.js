/**
 * Weak Scanner - Results Page JavaScript
 * 결과 페이지에서 스캔 상태 확인 및 결과 표시
 */

// Global variables
let currentScanId = null;
let statusPollInterval = null;

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

    console.log('Scan ID:', currentScanId);

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
        console.log('Scan status:', data.status);

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
        const response = await fetch(`${API_BASE_URL}/scan/${currentScanId}/results/`);

        if (!response.ok) {
            if (response.status === 404) {
                showError('스캔 결과를 찾을 수 없습니다.');
                return;
            }
            throw new Error('결과 로딩 실패');
        }

        const data = await response.json();
        console.log('Scan results loaded:', data);

        // Display results
        displayResults(data);

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
        document.getElementById('securityDetails').style.display = 'none';
    }

    // Display standards results
    if (data.standards_result) {
        document.getElementById('standardsScore').textContent = `${data.standards_result.overall_score || 0}점`;
        displayStandardsDetails(data.standards_result);
    } else {
        document.getElementById('standardsScore').textContent = '-';
        document.getElementById('standardsDetails').style.display = 'none';
    }

    // Display accessibility results
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
            { name: '보안 헤더 검사', field: 'security_headers', icon: '🛡️', id: 'security_headers' },
            { name: 'SSL/TLS 검사', field: 'ssl_tls_result', icon: '🔐', id: 'ssl_tls' },
            { name: 'XSS 취약점 스캔', field: 'xss_vulnerabilities', icon: '⚠️', id: 'xss' }
        ];
        tests.push(...defaultTests);
    }

    tests.forEach(test => {
        const testData = test.results || result[test.field];
        const item = document.createElement('div');
        item.className = 'step3-test-item';

        let statusClass = 'pass';
        let badgeText = '통과';
        let hasDetails = false;

        // Analyze test results
        if (testData) {
            if (testData.has_xss || testData.has_sqli || testData.misconfigured === true) {
                statusClass = 'fail';
                badgeText = `취약점 ${testData.total || 0}개`;
                hasDetails = true;
            } else if (testData.missing_count > 0) {
                statusClass = 'warning';
                badgeText = `누락 ${testData.missing_count}개`;
                hasDetails = true;
            } else if (testData.status === 'warning') {
                statusClass = 'warning';
                badgeText = '경고';
                hasDetails = true;
            } else {
                statusClass = 'pass';
                badgeText = '통과';
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

        // Add detailed information section if available
        if (hasDetails && testData) {
            const detailsDiv = document.createElement('div');
            detailsDiv.className = 'step3-test-details';
            detailsDiv.style.display = 'none';
            detailsDiv.innerHTML = '<div class="step3-details-content">상세 정보</div>';
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

    const tests = [
        { name: 'HTML 유효성', field: 'html_validation', icon: '📄' },
        { name: 'CSS 유효성', field: 'css_validation', icon: '🎨' },
        { name: '성능 최적화', field: 'performance', icon: '⚡' },
        { name: 'SEO 최적화', field: 'seo', icon: '🔍' }
    ];

    tests.forEach(test => {
        const testData = result[test.field];
        if (!testData) return;

        const item = document.createElement('div');
        item.className = 'step3-test-item';

        let statusClass = testData.is_valid || testData.score > 80 ? 'pass' : 'warning';
        let badgeText = testData.is_valid ? '통과' : `이슈 ${testData.errors?.length || 0}개`;

        item.innerHTML = `
            <div class="step3-test-header">
                <div class="step3-test-status">${test.icon}</div>
                <div class="step3-test-name">${test.name}</div>
                <div class="step3-test-result">
                    <span class="step3-test-badge ${statusClass}">${badgeText}</span>
                </div>
            </div>
        `;

        container.appendChild(item);
    });
}

/**
 * Display accessibility test details
 */
function displayAccessibilityDetails(result) {
    const container = document.getElementById('accessibilityTestList');
    container.innerHTML = '';

    const tests = [
        { name: '대체 텍스트', field: 'alt_text', icon: '🖼️' },
        { name: '폼 레이블', field: 'form_labels', icon: '📝' },
        { name: '제목 구조', field: 'heading_structure', icon: '📑' },
        { name: 'ARIA 속성', field: 'aria', icon: '♿' },
        { name: '색상 대비', field: 'contrast', icon: '🎨' },
        { name: '키보드 접근성', field: 'keyboard', icon: '⌨️' }
    ];

    tests.forEach(test => {
        const testData = result[test.field];
        if (!testData) return;

        const item = document.createElement('div');
        item.className = 'step3-test-item';

        let statusClass = testData.issues?.length > 0 ? 'warning' : 'pass';
        let badgeText = testData.issues?.length > 0 ? `이슈 ${testData.issues.length}개` : '통과';

        item.innerHTML = `
            <div class="step3-test-header">
                <div class="step3-test-status">${test.icon}</div>
                <div class="step3-test-name">${test.name}</div>
                <div class="step3-test-result">
                    <span class="step3-test-badge ${statusClass}">${badgeText}</span>
                </div>
            </div>
        `;

        container.appendChild(item);
    });
}

/**
 * Toggle details section visibility
 */
window.toggleDetails = function(headerElement) {
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
        alert('결과 페이지 URL이 클립보드에 복사되었습니다.');
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('URL 복사에 실패했습니다.');
    });
}

/**
 * Add missing styles for error section
 */
const style = document.createElement('style');
style.textContent = `
    .scan-info {
        text-align: center;
        margin-bottom: 30px;
        padding: 20px;
        background: #f8f9fa;
        border-radius: 8px;
    }

    .scan-url {
        font-size: 1.2em;
        font-weight: bold;
        color: #333;
        margin-bottom: 10px;
    }

    .scan-time {
        color: #666;
        font-size: 0.9em;
    }

    .error-container {
        text-align: center;
        padding: 60px 20px;
        max-width: 600px;
        margin: 0 auto;
    }

    .error-icon {
        font-size: 64px;
        margin-bottom: 20px;
    }

    .error-title {
        font-size: 24px;
        color: #333;
        margin-bottom: 10px;
    }

    .error-message {
        color: #666;
        font-size: 16px;
        margin-bottom: 30px;
    }

    .error-actions {
        margin-top: 30px;
    }

    .step3-btn-secondary {
        background: #6c757d;
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
        margin-left: 10px;
    }

    .step3-btn-secondary:hover {
        background: #5a6268;
    }
`;
document.head.appendChild(style);
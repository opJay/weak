/**
 * Weak Scanner - Input Page JavaScript
 * 메인 페이지에서 URL 입력 및 스캔 시작 처리
 */

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
    if (scanForm) {
        scanForm.addEventListener('submit', handleScanSubmit);
    }

    // URL 입력 필드에 포커스
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.focus();
    }
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

    // Show loading overlay
    showLoadingOverlay();

    // Disable submit button
    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.textContent = '스캔 시작 중...';
    }

    try {
        console.log('Starting scan request...', requestData);

        // Call API to start scan
        const response = await fetch(`${API_BASE_URL}/scan/start/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        });

        console.log('API response received:', response.status);
        const data = await response.json();

        if (!response.ok) {
            // 429 Too Many Requests 특별 처리
            if (response.status === 429) {
                const currentScans = data.current_scans || '?';
                const maxAllowed = data.max_allowed || '?';
                const message = data.message || '현재 스캔이 많이 실행 중입니다. 잠시 후 다시 시도해주세요.';

                alert(`⏳ 동시 스캔 제한 초과\n\n${message}\n\n현재 실행 중: ${currentScans}개\n최대 허용: ${maxAllowed}개`);

                hideLoadingOverlay();
                resetForm();
                return;
            }

            throw new Error(data.error || data.details || '스캔 요청 실패');
        }

        // 스캔이 성공적으로 시작되었으면 결과 페이지로 리다이렉트
        const scanId = data.scan_id;
        console.log('Scan started successfully. ID:', scanId);
        console.log('Redirecting to results page...');

        // 결과 페이지로 이동
        window.location.href = `/${scanId}/`;

    } catch (error) {
        console.error('Scan request error:', error);
        alert(`스캔 요청 실패: ${error.message}`);

        hideLoadingOverlay();
        resetForm();
    }
}

/**
 * Show loading overlay
 */
function showLoadingOverlay() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.style.display = 'flex';
    }
}

/**
 * Hide loading overlay
 */
function hideLoadingOverlay() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

/**
 * Reset form
 */
function resetForm() {
    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.textContent = '스캔 시작';
    }
}

/**
 * Add loading overlay styles if not exists
 */
const style = document.createElement('style');
style.textContent = `
    .loading-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(255, 255, 255, 0.95);
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        z-index: 9999;
    }

    .loading-spinner {
        width: 50px;
        height: 50px;
        border: 5px solid #f3f3f3;
        border-top: 5px solid #007bff;
        border-radius: 50%;
        animation: spin 1s linear infinite;
    }

    .loading-text {
        margin-top: 20px;
        font-size: 18px;
        color: #333;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
`;
document.head.appendChild(style);
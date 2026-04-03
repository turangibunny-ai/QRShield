class QRShield {
    constructor() {

        // Elements
        this.urlInput = document.getElementById('urlInput');
        this.scanBtn = document.getElementById('scanBtn');
        this.pasteBtn = document.getElementById('pasteBtn');
        this.clearBtn = document.getElementById('clearBtn');

        // QR Elements
        this.qrScanBtn = document.getElementById('qrScanBtn');
        this.qrTorchBtn = document.getElementById('qrTorchBtn');
        this.qrVideo = document.getElementById('qrVideo');
        this.qrCanvas = document.getElementById('qrCanvas');
        this.qrCtx = this.qrCanvas.getContext('2d');
        this.scanQrResult = document.getElementById('scanQrResult');

        // File Elements
        this.fileInput = document.getElementById('fileInput');
        this.fileBrowseBtn = document.getElementById('fileBrowseBtn');
        this.fileDropZone = document.getElementById('fileDropZone');
        this.scanFileResult = document.getElementById('scanFileResult');

        // Results
        this.results = document.getElementById('results');
        this.errorMsg = document.getElementById('errorMsg');
        this.spinner = document.getElementById('spinner');

        // State
        this.stream = null;
        this.torchEnabled = false;
        this.scanning = false;
        this.qrUrl = '';
        this.fileUrl = '';

        this.init();
    }

    init() {

        // URL Controls
        this.scanBtn.addEventListener('click', () => this.scanUrl());

        this.urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.scanUrl();
        });

        this.pasteBtn.addEventListener('click', () => this.pasteFromClipboard());
        this.clearBtn.addEventListener('click', () => this.clearInput());

        // QR Controls
        this.qrScanBtn.addEventListener('click', () => this.toggleQrScanner());
        this.qrTorchBtn.addEventListener('click', () => this.toggleTorch());
        this.scanQrResult.addEventListener('click', () => this.scanUrl());

        // File Controls
        this.fileBrowseBtn.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => this.handleFile(e.target.files[0]));
        this.scanFileResult.addEventListener('click', () => this.scanUrl());

        // Drag Drop
        this.setupDragDrop();

        // Tabs
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) =>
                this.switchTab(e.target.dataset.tab, e)
            );
        });

        this.urlInput.focus();
    }

    setupDragDrop() {

        const preventDefaults = (e) => {
            e.preventDefault();
            e.stopPropagation();
        };

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            this.fileDropZone.addEventListener(eventName, preventDefaults, false);
        });

        this.fileDropZone.addEventListener('drop', (e) => {
            const file = e.dataTransfer.files[0];
            this.handleFile(file);
        });
    }

    async pasteFromClipboard() {

        try {

            const text = await navigator.clipboard.readText();

            if (/^https?:\/\//i.test(text)) {
                this.urlInput.value = text;
                this.scanUrl();
            } else {
                this.showError('No valid URL in clipboard');
            }

        } catch (err) {

            this.showError('Clipboard access denied');

        }
    }

    clearInput() {
        this.urlInput.value = '';
        this.urlInput.focus();
    }

    switchTab(tabName, event) {

        document.querySelectorAll('.tab-btn')
            .forEach(btn => btn.classList.remove('active'));

        document.querySelectorAll('.scanner')
            .forEach(tab => tab.classList.remove('active'));

        event.target.classList.add('active');

        document.getElementById(tabName + 'Tab')
            .classList.add('active');
    }

    async toggleQrScanner() {

        if (this.scanning) {
            this.stopQrScanner();
        } else {
            await this.startQrScanner();
        }

    }

    async startQrScanner() {

        try {

            this.stream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: 'environment' }
            });

            this.qrVideo.srcObject = this.stream;

            await new Promise(resolve =>
                this.qrVideo.onloadedmetadata = resolve
            );

            this.qrCanvas.width = this.qrVideo.videoWidth;
            this.qrCanvas.height = this.qrVideo.videoHeight;

            this.scanning = true;

            this.qrScanBtn.innerHTML = '<i class="fas fa-stop"></i>';
            this.qrTorchBtn.classList.remove('hidden');

            this.scanQrCode();

        } catch (err) {

            this.showError('Camera access denied');

        }
    }

    stopQrScanner() {

        if (this.stream) {
            this.stream.getTracks().forEach(track => track.stop());
        }

        this.scanning = false;

        this.qrScanBtn.innerHTML = '<i class="fas fa-play"></i>';
        this.qrTorchBtn.classList.add('hidden');

        document.getElementById('qrResult').classList.add('hidden');
    }

    toggleTorch() {
        // Torch feature optional
    }

    scanQrCode() {

        if (!this.scanning) return;

        this.qrCtx.drawImage(
            this.qrVideo,
            0,
            0,
            this.qrCanvas.width,
            this.qrCanvas.height
        );

        const imageData = this.qrCtx.getImageData(
            0,
            0,
            this.qrCanvas.width,
            this.qrCanvas.height
        );

        const code = jsQR(
            imageData.data,
            imageData.width,
            imageData.height
        );

        if (code) {

            this.qrUrl = code.data;

            document.getElementById('qrUrl').textContent = this.qrUrl;

            document.getElementById('qrResult')
                .classList.remove('hidden');

            this.stopQrScanner();

            return;
        }

        requestAnimationFrame(() => this.scanQrCode());
    }

    handleFile(file) {

        if (!file || !file.type.startsWith('image/')) {
            this.showError('Please select an image file');
            return;
        }

        const reader = new FileReader();

        reader.onload = (e) => {

            const img = new Image();

            img.onload = () => {

                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');

                canvas.width = img.width;
                canvas.height = img.height;

                ctx.drawImage(img, 0, 0);

                const imageData = ctx.getImageData(
                    0,
                    0,
                    canvas.width,
                    canvas.height
                );

                const code = jsQR(
                    imageData.data,
                    canvas.width,
                    canvas.height
                );

                if (code) {

                    this.fileUrl = code.data;

                    document.getElementById('fileUrl')
                        .textContent = this.fileUrl;

                    document.getElementById('fileResult')
                        .classList.remove('hidden');

                    this.fileDropZone.classList.add('hidden');

                } else {

                    this.showError('No QR code found in image');

                }

            };

            img.src = e.target.result;
        };

        reader.readAsDataURL(file);
    }

    async scanUrl() {

        let url = this.urlInput.value.trim();

        if (this.fileUrl) {
            url = this.fileUrl;
            document.getElementById('sourceType').textContent = 'File QR';
        }
        else if (this.qrUrl) {
            url = this.qrUrl;
            document.getElementById('sourceType').textContent = 'Camera QR';
        }
        else {
            document.getElementById('sourceType').textContent = 'Direct URL';
        }

        if (!/^https?:\/\//i.test(url)) {
            this.showError('Please enter a valid URL or scan QR code');
            return;
        }

        this.resetUI();
        this.showLoading();

        try {

            const response = await fetch('/api/v1/check-url', {

                method: 'POST',

                headers: {
                    'Content-Type': 'application/json'
                },

                body: JSON.stringify({ url })

            });

            const data = await response.json();

            if (!response.ok)
                throw new Error(data.error || 'Scan failed');

            this.displayResults(data);

        } catch (error) {

            this.showError(error.message);

        } finally {

            this.hideLoading();

            this.urlInput.value = url;

        }
    }

    displayResults(data) {

        const scoreFill = document.getElementById('scoreFill');
        const scoreValue = document.getElementById('riskScore');

        scoreFill.style.width = `${data.risk_score}%`;
        scoreValue.textContent = data.risk_score;

        document.getElementById('statusText')
            .textContent = data.status;

        document.getElementById('adviceText')
            .textContent = data.advice;

        document.getElementById('scanTime')
            .textContent =
            `Scanned: ${new Date(data.scan_time).toLocaleString()}`;

        this.results.classList.remove('hidden');
    }

    resetUI() {

        this.errorMsg.classList.add('hidden');
        this.results.classList.add('hidden');

    }

    showLoading() {

        this.spinner.classList.remove('hidden');

    }

    hideLoading() {

        this.spinner.classList.add('hidden');

    }

    showError(msg) {

        this.errorMsg.textContent = msg;
        this.errorMsg.classList.remove('hidden');

    }
}

document.addEventListener('DOMContentLoaded', () => {
    new QRShield();
});
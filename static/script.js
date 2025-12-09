class RealTimeSpoofingLab {
    constructor() {
        this.socket = null;
        this.currentRole = initialRole;
        this.realIp = null;
        this.selectedMessageId = null;
        this.messageChart = null;
        
        this.initializeElements();
        this.init();
    }
    
    initializeElements() {
        // Role switching
        this.hackerBtn = document.getElementById('switch-to-hacker');
        this.defenderBtn = document.getElementById('switch-to-defender');
        this.hackerPanel = document.getElementById('hacker-panel');
        this.defenderPanel = document.getElementById('defender-panel');
        this.statsPanel = document.getElementById('stats-panel');
        this.educationPanel = document.getElementById('education-panel');
        
        // Connection status
        this.connectionDot = document.getElementById('connection-dot');
        this.connectionStatus = document.getElementById('connection-status');
        
        // Hacker elements
        this.realIpDisplay = document.getElementById('real-ip-display');
        this.legitMode = document.getElementById('mode-legit');
        this.spoofMode = document.getElementById('mode-spoof');
        this.spoofConfig = document.getElementById('spoof-config');
        this.spoofedIpInput = document.getElementById('spoofed-ip-input');
        this.generateRandomBtn = document.getElementById('generate-random-ip');
        this.quickIpButtons = document.querySelectorAll('.quick-ip-btn');
        this.hackerMessage = document.getElementById('hacker-message');
        this.previewIp = document.getElementById('preview-ip');
        this.previewMessage = document.getElementById('preview-message');
        this.sendMessageBtn = document.getElementById('send-message-btn');
        this.templateButtons = document.querySelectorAll('.template-btn');
        this.simulateButtons = document.querySelectorAll('.simulate-btn');
        
        // Hacker stats
        this.totalSent = document.getElementById('total-sent');
        this.spoofedSent = document.getElementById('spoofed-sent');
        this.detectedCount = document.getElementById('detected-count');
        this.successRate = document.getElementById('success-rate');
        
        // Defender elements
        this.messagesList = document.getElementById('messages-list');
        this.trafficFilter = document.getElementById('traffic-filter');
        this.analysisCard = document.getElementById('analysis-card');
        this.selectedMessageDetails = document.getElementById('selected-message-details');
        this.closeAnalysisBtn = document.getElementById('close-analysis');
        this.legitGuessBtn = document.querySelector('.legit-guess');
        this.spoofGuessBtn = document.querySelector('.spoof-guess');
        this.confidenceSlider = document.getElementById('confidence-slider');
        this.confidenceValue = document.getElementById('confidence-value');
        this.submitAnalysisBtn = document.getElementById('submit-analysis');
        this.resultCard = document.getElementById('result-card');
        this.resultContent = document.getElementById('result-content');
        
        // Defender stats
        this.totalAnalyzed = document.getElementById('total-analyzed');
        this.correctDetections = document.getElementById('correct-detections');
        this.incorrectDetections = document.getElementById('incorrect-detections');
        this.detectionAccuracy = document.getElementById('detection-accuracy');
        
        // System stats
        this.totalMessagesStat = document.getElementById('total-messages-stat');
        this.legitMessagesStat = document.getElementById('legit-messages-stat');
        this.spoofedMessagesStat = document.getElementById('spoofed-messages-stat');
        this.activeConnections = document.getElementById('active-connections');
        this.spoofingRateStat = document.getElementById('spoofing-rate-stat');
        this.detectionRate = document.getElementById('detection-rate');
        this.topSpoofedIps = document.getElementById('top-spoofed-ips');
        
        // System controls
        this.clearAllBtn = document.getElementById('clear-all-btn');
        this.refreshAllBtn = document.getElementById('refresh-all-btn');
        this.helpBtn = document.getElementById('help-btn');
        this.helpModal = document.getElementById('help-modal');
        
        // Mobile menu
        this.mobileMenuBtn = document.getElementById('mobile-menu-btn');
        this.mobileMenu = document.getElementById('mobile-menu');
        this.closeMenuBtn = document.getElementById('close-menu-btn');
        this.mobileMenuItems = document.querySelectorAll('.mobile-menu-item');
    }
    
    async init() {
        // Initialize Socket.IO connection
        this.initSocket();
        
        // Load client info
        await this.loadClientInfo();
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Update UI based on initial role
        this.updateRoleUI();
        
        // Initialize chart
        this.initChart();
        
        // Hide loading screen
        setTimeout(() => {
            document.getElementById('loading-screen').style.display = 'none';
        }, 1500);
    }
    
    initSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.connectionDot.className = 'status-dot connected';
            this.connectionStatus.textContent = 'Connected';
            toastr.success('Connected to IP Spoofing Lab');
            
            // Request message history
            this.socket.emit('request_history');
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.connectionDot.className = 'status-dot';
            this.connectionStatus.textContent = 'Disconnected';
            toastr.error('Disconnected from server');
        });
        
        this.socket.on('connection_established', (data) => {
            console.log('Connection established:', data);
            this.currentRole = data.role;
            this.updateRoleUI();
        });
        
        this.socket.on('new_message', (message) => {
            console.log('New message received:', message);
            this.addMessageToList(message);
            
            if (this.currentRole === 'defender') {
                this.showNotification('New message received', `${message.displayed_ip}: ${message.message.substring(0, 30)}...`);
            }
        });
        
        this.socket.on('message_sent', (data) => {
            toastr.success(data.message);
            this.updatePreview();
        });
        
        this.socket.on('analysis_result', (result) => {
            this.showAnalysisResult(result);
            this.updateDefenderStats();
        });
        
        this.socket.on('message_history', (data) => {
            console.log('Message history:', data);
            data.messages.forEach(message => this.addMessageToList(message));
        });
        
        this.socket.on('attack_simulated', (data) => {
            toastr.info(`Simulated ${data.name} with ${data.count} messages`);
        });
        
        this.socket.on('all_cleared', () => {
            this.messagesList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-envelope-open-text"></i>
                    <h4>All messages cleared</h4>
                    <p>Messages will appear here when hackers send them</p>
                </div>
            `;
            toastr.info('All messages cleared');
        });
        
        this.socket.on('error', (data) => {
            toastr.error(data.message);
        });
    }
    
    setupEventListeners() {
        // Role switching
        this.hackerBtn.addEventListener('click', () => this.switchRole('hacker'));
        this.defenderBtn.addEventListener('click', () => this.switchRole('defender'));
        
        // IP mode switching
        this.legitMode.addEventListener('change', () => this.updateIpMode());
        this.spoofMode.addEventListener('change', () => this.updateIpMode());
        
        // IP generation
        this.generateRandomBtn.addEventListener('click', () => this.generateRandomIp());
        this.quickIpButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.spoofedIpInput.value = e.target.dataset.ip;
                this.updatePreview();
            });
        });
        
        // Message composition
        this.hackerMessage.addEventListener('input', () => this.updatePreview());
        this.templateButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.applyTemplate(e.target.dataset.template);
            });
        });
        
        // Message sending
        this.sendMessageBtn.addEventListener('click', () => this.sendMessage());
        this.simulateButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.simulateAttack(e.target.dataset.type);
            });
        });
        
        // Defender analysis
        this.trafficFilter.addEventListener('change', () => this.filterMessages());
        this.closeAnalysisBtn.addEventListener('click', () => this.closeAnalysis());
        this.legitGuessBtn.addEventListener('click', () => this.setGuess('legitimate'));
        this.spoofGuessBtn.addEventListener('click', () => this.setGuess('spoofed'));
        this.confidenceSlider.addEventListener('input', (e) => {
            this.confidenceValue.textContent = e.target.value;
        });
        this.submitAnalysisBtn.addEventListener('click', () => this.submitAnalysis());
        
        // System controls
        this.clearAllBtn.addEventListener('click', () => this.clearAllMessages());
        this.refreshAllBtn.addEventListener('click', () => this.refreshAll());
        this.helpBtn.addEventListener('click', () => this.showHelp());
        
        // Mobile menu
        this.mobileMenuBtn.addEventListener('click', () => this.toggleMobileMenu());
        this.closeMenuBtn.addEventListener('click', () => this.toggleMobileMenu());
        this.mobileMenuItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const target = e.target.getAttribute('href').substring(1);
                this.showPanel(target);
                this.toggleMobileMenu();
            });
        });
        
        // Close modal when clicking outside
        window.addEventListener('click', (e) => {
            if (e.target === this.helpModal) {
                this.hideHelp();
            }
        });
        
        // Close modal with Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideHelp();
            }
        });
    }
    
    async loadClientInfo() {
        try {
            const response = await fetch('/client_info');
            const data = await response.json();
            
            this.realIp = data.real_ip;
            this.realIpDisplay.innerHTML = `
                <i class="fas fa-network-wired"></i>
                <span>${this.realIp}</span>
            `;
            
            // Update quick IP buttons with examples
            data.spoof_examples.forEach((example, index) => {
                if (this.quickIpButtons[index]) {
                    this.quickIpButtons[index].dataset.ip = example.ip;
                    this.quickIpButtons[index].textContent = example.ip;
                    this.quickIpButtons[index].title = example.desc;
                }
            });
            
        } catch (error) {
            console.error('Error loading client info:', error);
            this.realIpDisplay.innerHTML = `
                <i class="fas fa-exclamation-triangle"></i>
                <span>Unable to detect IP</span>
            `;
        }
    }
    
    switchRole(role) {
        if (this.currentRole === role) return;
        
        this.currentRole = role;
        
        // Update server session
        fetch(`/switch_role/${role}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    this.currentRole = data.role;
                    this.updateRoleUI();
                    toastr.info(`Switched to ${role} role`);
                }
            })
            .catch(error => {
                console.error('Error switching role:', error);
                toastr.error('Failed to switch role');
            });
    }
    
    updateRoleUI() {
        // Update button states
        this.hackerBtn.classList.remove('active');
        this.defenderBtn.classList.remove('active');
        
        if (this.currentRole === 'hacker') {
            this.hackerBtn.classList.add('active');
            this.hackerPanel.classList.add('active');
            this.defenderPanel.classList.remove('active');
        } else {
            this.defenderBtn.classList.add('active');
            this.hackerPanel.classList.remove('active');
            this.defenderPanel.classList.add('active');
        }
        
        // Update UI based on role
        if (this.currentRole === 'hacker') {
            this.updatePreview();
            this.updateHackerStats();
        } else {
            this.updateDefenderStats();
        }
    }
    
    updateIpMode() {
        if (this.spoofMode.checked) {
            this.spoofConfig.style.display = 'block';
            this.previewIp.textContent = this.spoofedIpInput.value;
            this.previewIp.className = 'preview-ip spoofed';
        } else {
            this.spoofConfig.style.display = 'none';
            this.previewIp.textContent = this.realIp;
            this.previewIp.className = 'preview-ip legitimate';
        }
    }
    
    generateRandomIp() {
        const octets = Array.from({length: 4}, () => Math.floor(Math.random() * 256));
        
        // Common private IP ranges
        const ranges = [
            () => `192.168.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
            () => `10.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
            () => `172.${Math.floor(Math.random() * 16 + 16)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
        ];
        
        const randomRange = ranges[Math.floor(Math.random() * ranges.length)];
        this.spoofedIpInput.value = randomRange();
        this.updatePreview();
    }
    
    applyTemplate(template) {
        const templates = {
            normal: "Hello, this is a normal message from the network administrator.",
            phishing: "URGENT: Your account security has been compromised. Click http://verify-account.com to reset your password immediately.",
            attack: "Initiating distributed denial-of-service attack from multiple spoofed sources..."
        };
        
        this.hackerMessage.value = templates[template] || templates.normal;
        this.updatePreview();
    }
    
    updatePreview() {
        const message = this.hackerMessage.value;
        
        if (message) {
            const preview = message.length > 50 ? 
                message.substring(0, 50) + '...' : message;
            this.previewMessage.textContent = preview;
        } else {
            this.previewMessage.textContent = '[Type a message above]';
        }
        
        // Update IP preview
        if (this.spoofMode.checked) {
            this.previewIp.textContent = this.spoofedIpInput.value || '192.168.1.100';
            this.previewIp.className = 'preview-ip spoofed';
        } else {
            this.previewIp.textContent = this.realIp;
            this.previewIp.className = 'preview-ip legitimate';
        }
    }
    
    sendMessage() {
        const message = this.hackerMessage.value.trim();
        
        if (!message) {
            toastr.warning('Please enter a message');
            return;
        }
        
        const useSpoofing = this.spoofMode.checked;
        const spoofedIp = this.spoofedIpInput.value.trim();
        
        if (useSpoofing && !this.validateIp(spoofedIp)) {
            toastr.error('Please enter a valid IP address');
            return;
        }
        
        // Disable send button temporarily
        this.sendMessageBtn.disabled = true;
        this.sendMessageBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> SENDING...';
        
        // Send via WebSocket
        this.socket.emit('send_message', {
            message: message,
            spoofed_ip: spoofedIp,
            use_spoofing: useSpoofing
        });
        
        // Clear message and re-enable button after 1 second
        setTimeout(() => {
            this.hackerMessage.value = '';
            this.sendMessageBtn.disabled = false;
            this.sendMessageBtn.innerHTML = '<i class="fas fa-paper-plane"></i> SEND MESSAGE';
            this.updatePreview();
        }, 1000);
    }
    
    simulateAttack(type) {
        this.socket.emit('simulate_attack', { type: type });
    }
    
    validateIp(ip) {
        const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        return ipPattern.test(ip);
    }
    
    addMessageToList(message) {
        // Remove empty state if present
        const emptyState = this.messagesList.querySelector('.empty-state');
        if (emptyState) {
            emptyState.remove();
        }
        
        const messageElement = this.createMessageElement(message);
        this.messagesList.insertBefore(messageElement, this.messagesList.firstChild);
        
        // Limit to 50 messages
        const messages = this.messagesList.querySelectorAll('.message-item');
        if (messages.length > 50) {
            this.messagesList.removeChild(messages[messages.length - 1]);
        }
    }
    
    createMessageElement(message) {
        const div = document.createElement('div');
        div.className = 'message-item';
        div.dataset.id = message.id;
        div.dataset.spoofed = message.is_spoofed;
        
        const time = new Date().toLocaleTimeString([], { 
            hour: '2-digit', 
            minute: '2-digit',
            second: '2-digit'
        });
        
        const messagePreview = message.message.length > 80 ? 
            message.message.substring(0, 80) + '...' : message.message;
        
        div.innerHTML = `
            <div class="message-header">
                <div class="sender-info">
                    <span class="sender-ip ${message.is_spoofed ? 'spoofed' : 'legitimate'}">
                        ${message.displayed_ip}
                        ${message.is_spoofed ? ' <i class="fas fa-user-secret"></i>' : ' <i class="fas fa-user-check"></i>'}
                    </span>
                </div>
                <div class="message-time">${message.timestamp || time}</div>
            </div>
            <div class="message-content">${this.escapeHtml(messagePreview)}</div>
            ${message.detection_guess ? `
                <div class="message-analysis">
                    <span class="analysis-badge ${message.detection_correct ? 'correct' : 'incorrect'}">
                        ${message.detection_guess === 'spoofed' ? 'Spoofed' : 'Legitimate'} 
                        ${message.detection_correct ? '✓' : '✗'}
                    </span>
                </div>
            ` : ''}
        `;
        
        // Add click event for analysis
        div.addEventListener('click', () => {
            this.selectMessageForAnalysis(message);
        });
        
        return div;
    }
    
    selectMessageForAnalysis(message) {
        this.selectedMessageId = message.id;
        
        // Highlight selected message
        document.querySelectorAll('.message-item').forEach(item => {
            item.classList.remove('selected');
        });
        document.querySelector(`.message-item[data-id="${message.id}"]`).classList.add('selected');
        
        // Show analysis card
        this.analysisCard.style.display = 'block';
        this.resultCard.style.display = 'none';
        
        // Display message details
        const time = new Date().toLocaleTimeString([], { 
            hour: '2-digit', 
            minute: '2-digit',
            second: '2-digit'
        });
        
        this.selectedMessageDetails.innerHTML = `
            <div class="message-analysis-details">
                <div class="detail-item">
                    <span class="detail-label">Sender IP:</span>
                    <span class="detail-value ip">${message.displayed_ip}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Time:</span>
                    <span class="detail-value">${message.timestamp || time}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Message:</span>
                    <span class="detail-value">${this.escapeHtml(message.message)}</span>
                </div>
                ${message.attack_type ? `
                    <div class="detail-item">
                        <span class="detail-label">Attack Type:</span>
                        <span class="detail-value">${message.attack_type.toUpperCase()}</span>
                    </div>
                ` : ''}
            </div>
        `;
        
        // Reset guess buttons
        this.legitGuessBtn.classList.remove('active');
        this.spoofGuessBtn.classList.remove('active');
        
        // Scroll to analysis card on mobile
        if (deviceType === 'mobile') {
            this.analysisCard.scrollIntoView({ behavior: 'smooth' });
        }
    }
    
    setGuess(guess) {
        // Reset both buttons
        this.legitGuessBtn.classList.remove('active');
        this.spoofGuessBtn.classList.remove('active');
        
        // Activate selected button
        if (guess === 'legitimate') {
            this.legitGuessBtn.classList.add('active');
        } else {
            this.spoofGuessBtn.classList.add('active');
        }
    }
    
    submitAnalysis() {
        if (!this.selectedMessageId) {
            toastr.warning('Please select a message to analyze');
            return;
        }
        
        const activeGuess = document.querySelector('.guess-btn.active');
        if (!activeGuess) {
            toastr.warning('Please select Legitimate or Spoofed');
            return;
        }
        
        const guess = activeGuess.dataset.guess;
        const confidence = this.confidenceSlider.value;
        
        // Disable submit button
        this.submitAnalysisBtn.disabled = true;
        this.submitAnalysisBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ANALYZING...';
        
        // Send analysis via WebSocket
        this.socket.emit('analyze_message', {
            message_id: this.selectedMessageId,
            guess: guess,
            confidence: parseInt(confidence)
        });
    }
    
    showAnalysisResult(result) {
        // Re-enable submit button
        this.submitAnalysisBtn.disabled = false;
        this.submitAnalysisBtn.innerHTML = '<i class="fas fa-check-circle"></i> ANALYZE MESSAGE';
        
        // Show result card
        this.resultCard.style.display = 'block';
        
        const resultClass = result.is_correct ? 'correct' : 'incorrect';
        const resultIcon = result.is_correct ? 'fa-check-circle' : 'fa-times-circle';
        const resultText = result.is_correct ? 'CORRECT!' : 'INCORRECT';
        
        this.resultContent.innerHTML = `
            <div class="result-header ${resultClass}">
                <i class="fas ${resultIcon}"></i>
                <h3>${resultText}</h3>
            </div>
            
            <div class="result-details">
                <div class="result-item">
                    <span class="result-label">Your Guess:</span>
                    <span class="result-value">${result.your_guess.toUpperCase()}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Actual:</span>
                    <span class="result-value">${result.actual_status.toUpperCase()}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Real IP:</span>
                    <span class="result-value ip">${result.real_ip}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Displayed IP:</span>
                    <span class="result-value ip">${result.displayed_ip}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Confidence:</span>
                    <span class="result-value">${result.confidence}%</span>
                </div>
            </div>
            
            <div class="result-hints">
                <h5><i class="fas fa-lightbulb"></i> Analysis Hints:</h5>
                <ul>
                    ${result.hints.map(hint => `<li>${hint}</li>`).join('')}
                </ul>
            </div>
            
            <div class="result-stats">
                <div class="user-stats">
                    <div class="stat">
                        <div class="stat-number">${result.user_stats.accuracy}%</div>
                        <div class="stat-label">Your Accuracy</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">${result.user_stats.correct}</div>
                        <div class="stat-label">Correct</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">${result.user_stats.total_analyzed - result.user_stats.correct}</div>
                        <div class="stat-label">Incorrect</div>
                    </div>
                </div>
            </div>
        `;
        
        // Update the message in the list
        const messageItem = document.querySelector(`.message-item[data-id="${result.message_id}"]`);
        if (messageItem) {
            const analysisBadge = messageItem.querySelector('.analysis-badge') || document.createElement('div');
            analysisBadge.className = `analysis-badge ${result.is_correct ? 'correct' : 'incorrect'}`;
            analysisBadge.innerHTML = `
                ${result.your_guess === 'spoofed' ? 'Spoofed' : 'Legitimate'} 
                ${result.is_correct ? '✓' : '✗'}
            `;
            
            if (!messageItem.querySelector('.message-analysis')) {
                const analysisDiv = document.createElement('div');
                analysisDiv.className = 'message-analysis';
                analysisDiv.appendChild(analysisBadge);
                messageItem.appendChild(analysisDiv);
            }
        }
        
        // Scroll to results on mobile
        if (deviceType === 'mobile') {
            this.resultCard.scrollIntoView({ behavior: 'smooth' });
        }
    }
    
    closeAnalysis() {
        this.analysisCard.style.display = 'none';
        this.resultCard.style.display = 'none';
        this.selectedMessageId = null;
        
        // Clear selection
        document.querySelectorAll('.message-item').forEach(item => {
            item.classList.remove('selected');
        });
    }
    
    filterMessages() {
        const filter = this.trafficFilter.value;
        const messages = this.messagesList.querySelectorAll('.message-item');
        
        messages.forEach(message => {
            const isSpoofed = message.dataset.spoofed === 'true';
            
            switch(filter) {
                case 'all':
                    message.style.display = 'block';
                    break;
                case 'spoofed':
                    message.style.display = isSpoofed ? 'block' : 'none';
                    break;
                case 'legitimate':
                    message.style.display = !isSpoofed ? 'block' : 'none';
                    break;
            }
        });
    }
    
    async updateHackerStats() {
        try {
            const response = await fetch('/stats');
            const data = await response.json();
            
            this.totalSent.textContent = data.total_messages;
            this.spoofedSent.textContent = data.spoofed_messages;
            this.detectedCount.textContent = data.correct_detections;
            
            const successRate = data.total_messages > 0 ? 
                Math.round((data.spoofed_messages / data.total_messages) * 100) : 0;
            this.successRate.textContent = `${successRate}%`;
            
        } catch (error) {
            console.error('Error updating hacker stats:', error);
        }
    }
    
    async updateDefenderStats() {
        try {
            const response = await fetch('/stats');
            const data = await response.json();
            
            this.totalAnalyzed.textContent = data.correct_detections || 0;
            
            // Calculate accuracy
            const accuracy = data.total_messages > 0 ? 
                Math.round((data.correct_detections / data.total_messages) * 100) : 0;
            this.detectionAccuracy.textContent = `${accuracy}%`;
            
        } catch (error) {
            console.error('Error updating defender stats:', error);
        }
    }
    
    async updateSystemStats() {
        try {
            const response = await fetch('/stats');
            const data = await response.json();
            
            // Update main stats
            this.totalMessagesStat.textContent = data.total_messages;
            this.legitMessagesStat.textContent = data.legitimate_messages;
            this.spoofedMessagesStat.textContent = data.spoofed_messages;
            this.spoofingRateStat.textContent = `${data.spoofing_rate}%`;
            
            // Update detection rate
            const detectionRate = data.total_messages > 0 ? 
                Math.round((data.correct_detections / data.total_messages) * 100) : 0;
            this.detectionRate.textContent = `${detectionRate}%`;
            
            // Update top spoofed IPs
            this.topSpoofedIps.innerHTML = data.top_spoofed_ips.map((ip, index) => `
                <div class="top-ip-item">
                    <span class="ip-rank">${index + 1}</span>
                    <span class="ip-address">${ip.ip}</span>
                    <span class="ip-count">${ip.count}x</span>
                </div>
            `).join('');
            
            // Update chart
            this.updateChart(data);
            
        } catch (error) {
            console.error('Error updating system stats:', error);
        }
    }
    
    initChart() {
        const ctx = document.getElementById('attack-chart').getContext('2d');
        this.messageChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Legitimate', 'Spoofed', 'Detected'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: [
                        'rgba(40, 167, 69, 0.8)',
                        'rgba(220, 53, 69, 0.8)',
                        'rgba(0, 123, 255, 0.8)'
                    ],
                    borderColor: [
                        'rgba(40, 167, 69, 1)',
                        'rgba(220, 53, 69, 1)',
                        'rgba(0, 123, 255, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#ffffff',
                            font: {
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#ffffff',
                        bodyColor: '#ffffff'
                    }
                }
            }
        });
    }
    
    updateChart(data) {
        if (this.messageChart) {
            this.messageChart.data.datasets[0].data = [
                data.legitimate_messages,
                data.spoofed_messages,
                data.correct_detections
            ];
            this.messageChart.update();
        }
    }
    
    async clearAllMessages() {
        if (!confirm('Are you sure you want to clear ALL messages? This cannot be undone.')) {
            return;
        }
        
        try {
            const response = await fetch('/clear_all', {
                method: 'POST'
            });
            
            if (response.ok) {
                // Clear will be handled by socket event
                this.socket.emit('request_history');
                this.updateSystemStats();
            }
        } catch (error) {
            console.error('Error clearing messages:', error);
            toastr.error('Failed to clear messages');
        }
    }
    
    async refreshAll() {
        toastr.info('Refreshing data...');
        
        await this.loadClientInfo();
        await this.updateSystemStats();
        
        if (this.currentRole === 'hacker') {
            await this.updateHackerStats();
        } else {
            await this.updateDefenderStats();
        }
        
        toastr.success('Data refreshed');
    }
    
    showHelp() {
        this.helpModal.style.display = 'flex';
        this.helpModal.classList.add('active');
    }
    
    hideHelp() {
        this.helpModal.style.display = 'none';
        this.helpModal.classList.remove('active');
    }
    
    toggleMobileMenu() {
        this.mobileMenu.classList.toggle('active');
    }
    
    showPanel(panelId) {
        // Hide all panels
        document.querySelectorAll('.panel').forEach(panel => {
            panel.classList.remove('active');
        });
        
        // Show selected panel
        const panel = document.getElementById(panelId);
        if (panel) {
            panel.classList.add('active');
        }
    }
    
    showNotification(title, message) {
        // Check if browser supports notifications
        if (!("Notification" in window)) {
            return;
        }
        
        // Check if permission is already granted
        if (Notification.permission === "granted") {
            new Notification(title, { body: message });
        }
        // Otherwise, ask for permission
        else if (Notification.permission !== "denied") {
            Notification.requestPermission().then(permission => {
                if (permission === "granted") {
                    new Notification(title, { body: message });
                }
            });
        }
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.spoofingLab = new RealTimeSpoofingLab();
});
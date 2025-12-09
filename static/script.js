/**
 * Real-Time IP Spoofing Lab - Main JavaScript
 * Handles WebSocket communication, UI interactions, and real-time updates
 */

class RealTimeSpoofingLab {
    constructor() {
        this.socket = null;
        this.currentRole = initialData.role;
        this.currentPanel = this.currentRole === 'hacker' ? 'hacker' : 'defender';
        this.realIp = initialData.realIp;
        this.selectedMessageId = null;
        this.messageChart = null;
        this.defenderChart = null;
        this.attackChart = null;
        this.connectionStartTime = Date.now();
        this.messageCount = 0;
        this.analysisCount = 0;
        
        this.initializeElements();
        this.init();
    }
    
    initializeElements() {
        // Header elements
        this.hackerBtn = document.getElementById('switch-to-hacker');
        this.defenderBtn = document.getElementById('switch-to-defender');
        this.connectionDot = document.getElementById('connection-dot');
        this.connectionStatus = document.getElementById('connection-status');
        this.connectionsCount = document.getElementById('connections-count');
        this.menuToggle = document.getElementById('menu-toggle');
        this.mobileNav = document.getElementById('mobile-nav');
        this.navClose = document.getElementById('nav-close');
        this.navItems = document.querySelectorAll('.nav-item');
        
        // Hacker elements
        this.realIpDisplay = document.getElementById('real-ip-display');
        this.legitMode = document.getElementById('mode-legit');
        this.spoofMode = document.getElementById('mode-spoof');
        this.spoofConfig = document.getElementById('spoof-config');
        this.spoofedIpInput = document.getElementById('spoofed-ip-input');
        this.generateRandomBtn = document.getElementById('generate-random-ip');
        this.validateIpBtn = document.getElementById('validate-ip');
        this.ipValidation = document.getElementById('ip-validation');
        this.quickIpButtons = document.querySelectorAll('.quick-ip-btn');
        this.hackerMessage = document.getElementById('hacker-message');
        this.charCount = document.getElementById('char-count');
        this.clearMessageBtn = document.getElementById('clear-message');
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
        this.refreshHackerStatsBtn = document.getElementById('refresh-hacker-stats');
        
        // Defender elements
        this.trafficFilter = document.getElementById('traffic-filter');
        this.refreshTrafficBtn = document.getElementById('refresh-traffic');
        this.totalMessagesCount = document.getElementById('total-messages-count');
        this.suspiciousCount = document.getElementById('suspicious-count');
        this.analyzedCount = document.getElementById('analyzed-count');
        this.alertsCount = document.getElementById('alert-number');
        this.messagesList = document.getElementById('messages-list');
        this.analysisCard = document.getElementById('analysis-card');
        this.selectedMessageDetails = document.getElementById('selected-message-details');
        this.closeAnalysisBtn = document.getElementById('close-analysis');
        this.skipAnalysisBtn = document.getElementById('skip-analysis');
        this.legitGuessBtn = document.querySelector('.legit-guess');
        this.spoofGuessBtn = document.querySelector('.spoof-guess');
        this.confidenceSlider = document.getElementById('confidence-slider');
        this.confidenceValue = document.getElementById('confidence-value');
        this.submitAnalysisBtn = document.getElementById('submit-analysis');
        this.resultCard = document.getElementById('result-card');
        this.resultContent = document.getElementById('result-content');
        this.closeResultBtn = document.getElementById('close-result');
        
        // Defender stats
        this.totalAnalyzed = document.getElementById('total-analyzed');
        this.correctDetections = document.getElementById('correct-detections');
        this.incorrectDetections = document.getElementById('incorrect-detections');
        this.detectionAccuracy = document.getElementById('detection-accuracy');
        this.refreshDefenderStatsBtn = document.getElementById('refresh-defender-stats');
        
        // System stats
        this.totalMessagesStat = document.getElementById('total-messages-stat');
        this.legitMessagesStat = document.getElementById('legit-messages-stat');
        this.spoofedMessagesStat = document.getElementById('spoofed-messages-stat');
        this.activeConnections = document.getElementById('active-connections');
        this.spoofingRateStat = document.getElementById('spoofing-rate-stat');
        this.detectionRate = document.getElementById('detection-rate');
        this.responseTime = document.getElementById('response-time');
        this.topSpoofedIps = document.getElementById('top-spoofed-ips');
        this.activityTimeline = document.getElementById('activity-timeline');
        this.exportDataBtn = document.getElementById('export-data');
        
        // Logs panel
        this.clearLogsBtn = document.getElementById('clear-logs');
        this.logsList = document.getElementById('logs-list');
        this.totalLogs = document.getElementById('total-logs');
        this.ddosLogs = document.getElementById('ddos-logs');
        this.phishingLogs = document.getElementById('phishing-logs');
        this.mitmLogs = document.getElementById('mitm-logs');
        
        // System controls
        this.clearAllBtn = document.getElementById('clear-all-btn');
        this.refreshAllBtn = document.getElementById('refresh-all-btn');
        this.helpBtn = document.getElementById('help-btn');
        this.helpModal = document.getElementById('help-modal');
        this.closeModalBtn = document.querySelector('.close-modal');
        
        // Server status
        this.serverTime = document.getElementById('server-time');
        this.serverUptime = document.getElementById('server-uptime');
        
        // Mobile IP display
        this.mobileIpDisplay = document.getElementById('mobile-ip-display');
    }
    
    async init() {
        console.log('🚀 Initializing IP Spoofing Lab...');
        console.log(`   Role: ${this.currentRole}`);
        console.log(`   Device: ${initialData.device}`);
        console.log(`   Session: ${initialData.sessionId}`);
        
        // Initialize Socket.IO connection
        this.initSocket();
        
        // Load client info
        await this.loadClientInfo();
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Initialize charts
        this.initCharts();
        
        // Update UI based on initial role
        this.updateRoleUI();
        
        // Start background tasks
        this.startBackgroundTasks();
        
        // Hide loading screen
        setTimeout(() => {
            const loadingScreen = document.getElementById('loading-screen');
            loadingScreen.style.opacity = '0';
            setTimeout(() => {
                loadingScreen.style.display = 'none';
            }, 300);
        }, 1500);
    }
    
    initSocket() {
        // Connect to Socket.IO server
        this.socket = io({
            transports: ['websocket', 'polling'],
            upgrade: true,
            reconnection: true,
            reconnectionAttempts: 10,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            timeout: 20000
        });
        
        // Socket event handlers
        this.socket.on('connect', () => {
            console.log('✅ Connected to server with ID:', this.socket.id);
            this.connectionDot.className = 'status-dot connected';
            this.connectionStatus.textContent = 'Connected';
            this.connectionStatus.style.color = '#44ff44';
            
            toastr.success('Connected to IP Spoofing Lab', '', {
                timeOut: 2000,
                positionClass: initialData.device === 'mobile' ? 'toast-bottom-full-width' : 'toast-top-right'
            });
            
            // Request message history
            this.socket.emit('request_history');
            
            // Update connection start time
            this.connectionStartTime = Date.now();
        });
        
        this.socket.on('disconnect', (reason) => {
            console.log('❌ Disconnected from server:', reason);
            this.connectionDot.className = 'status-dot';
            this.connectionStatus.textContent = 'Disconnected';
            this.connectionStatus.style.color = '#ff4444';
            
            if (reason === 'io server disconnect') {
                toastr.error('Server disconnected. Please refresh the page.');
            } else {
                toastr.warning('Connection lost. Reconnecting...');
            }
        });
        
        this.socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            this.connectionStatus.textContent = 'Connection Failed';
            this.connectionStatus.style.color = '#ff4444';
            
            toastr.error('Failed to connect to server. Please check:', {
                timeOut: 5000,
                closeButton: true
            });
            
            toastr.info('1. Server is running<br>2. Correct IP address<br>3. Firewall settings', {
                timeOut: 5000,
                closeButton: true
            });
        });
        
        this.socket.on('connection_established', (data) => {
            console.log('Connection established:', data);
            this.currentRole = data.role;
            this.updateRoleUI();
            this.updateConnectionsCount(data.active_connections);
        });
        
        this.socket.on('connections_updated', (data) => {
            this.updateConnectionsCount(data.count);
        });
        
        this.socket.on('new_message', (message) => {
            console.log('📨 New message received:', message);
            this.messageCount++;
            this.addMessageToList(message);
            
            if (this.currentRole === 'defender') {
                this.showNotification(
                    'New Message Received',
                    `${message.displayed_ip}: ${message.message.substring(0, 50)}...`
                );
                
                // Update alerts count
                if (message.is_spoofed) {
                    const currentAlerts = parseInt(this.alertsCount.textContent) || 0;
                    this.alertsCount.textContent = currentAlerts + 1;
                }
            }
            
            // Update traffic stats
            this.updateTrafficStats();
            
            // Auto-scroll for defender
            if (this.currentRole === 'defender' && initialData.device === 'mobile') {
                this.messagesList.scrollTop = 0;
            }
        });
        
        this.socket.on('message_sent', (data) => {
            console.log('✅ Message sent:', data);
            
            toastr.success(data.message, '', {
                timeOut: 3000,
                positionClass: initialData.device === 'mobile' ? 'toast-bottom-full-width' : 'toast-top-right'
            });
            
            this.updatePreview();
            this.updateHackerStats();
        });
        
        this.socket.on('analysis_result', (result) => {
            console.log('🔍 Analysis result:', result);
            this.analysisCount++;
            this.showAnalysisResult(result);
            this.updateDefenderStats();
            this.updateSystemStats();
        });
        
        this.socket.on('message_analyzed', (data) => {
            console.log('📊 Message analyzed:', data);
            
            // Update the message in the list
            const messageItem = document.querySelector(`.message-item[data-id="${data.message_id}"]`);
            if (messageItem) {
                this.updateMessageStatus(messageItem, data);
            }
            
            this.updateTrafficStats();
        });
        
        this.socket.on('message_history', (data) => {
            console.log('📚 Message history received:', data.total, 'messages');
            
            // Clear current list
            this.messagesList.innerHTML = '';
            
            if (data.messages && data.messages.length > 0) {
                data.messages.forEach(message => this.addMessageToList(message));
            } else {
                this.showEmptyState();
            }
            
            this.updateTrafficStats();
        });
        
        this.socket.on('attack_simulated', (data) => {
            console.log('🎮 Attack simulated:', data);
            
            toastr.info(`Simulated ${data.name}: ${data.description}`, '', {
                timeOut: 4000,
                positionClass: initialData.device === 'mobile' ? 'toast-bottom-full-width' : 'toast-top-right'
            });
        });
        
        this.socket.on('all_cleared', () => {
            console.log('🗑️ All messages cleared');
            this.showEmptyState();
            this.messageCount = 0;
            this.analysisCount = 0;
            this.updateAllStats();
            
            toastr.info('All messages and statistics have been cleared', '', {
                timeOut: 3000,
                positionClass: initialData.device === 'mobile' ? 'toast-bottom-full-width' : 'toast-top-right'
            });
        });
        
        this.socket.on('role_switched', (data) => {
            console.log('🔄 Role switched:', data);
            
            if (data.session_id !== initialData.sessionId) {
                toastr.info(`Another user switched to ${data.role} role`);
            }
        });
        
        this.socket.on('error', (data) => {
            console.error('❌ Socket error:', data);
            
            toastr.error(data.message || 'An error occurred', '', {
                timeOut: 4000,
                closeButton: true
            });
        });
    }
    
    setupEventListeners() {
        // Role switching
        this.hackerBtn.addEventListener('click', () => this.switchRole('hacker'));
        this.defenderBtn.addEventListener('click', () => this.switchRole('defender'));
        
        // IP mode switching
        this.legitMode.addEventListener('change', () => this.updateIpMode());
        this.spoofMode.addEventListener('change', () => this.updateIpMode());
        
        // IP configuration
        this.generateRandomBtn.addEventListener('click', () => this.generateRandomIp());
        this.validateIpBtn.addEventListener('click', () => this.validateCurrentIp());
        this.spoofedIpInput.addEventListener('input', () => this.updatePreview());
        this.spoofedIpInput.addEventListener('blur', () => this.validateCurrentIp());
        
        this.quickIpButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const ip = e.currentTarget.dataset.ip;
                this.spoofedIpInput.value = ip;
                this.updatePreview();
                this.validateCurrentIp();
                toastr.info(`Selected IP: ${ip}`);
            });
        });
        
        // Message composition
        this.hackerMessage.addEventListener('input', () => {
            this.updatePreview();
            this.updateCharCount();
        });
        
        this.clearMessageBtn.addEventListener('click', () => {
            this.hackerMessage.value = '';
            this.updatePreview();
            this.updateCharCount();
            toastr.info('Message cleared');
        });
        
        this.templateButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.applyTemplate(e.currentTarget.dataset.template);
            });
        });
        
        // Message sending
        this.sendMessageBtn.addEventListener('click', () => this.sendMessage());
        
        // Attack simulations
        this.simulateButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.simulateAttack(e.currentTarget.dataset.type);
            });
        });
        
        // Defender analysis
        this.trafficFilter.addEventListener('change', () => this.filterMessages());
        this.refreshTrafficBtn.addEventListener('click', () => this.refreshTraffic());
        this.closeAnalysisBtn.addEventListener('click', () => this.closeAnalysis());
        this.skipAnalysisBtn.addEventListener('click', () => this.skipAnalysis());
        this.legitGuessBtn.addEventListener('click', () => this.setGuess('legitimate'));
        this.spoofGuessBtn.addEventListener('click', () => this.setGuess('spoofed'));
        
        this.confidenceSlider.addEventListener('input', (e) => {
            this.confidenceValue.textContent = e.target.value;
        });
        
        this.submitAnalysisBtn.addEventListener('click', () => this.submitAnalysis());
        this.closeResultBtn.addEventListener('click', () => this.closeResult());
        
        // Stats refresh
        this.refreshHackerStatsBtn.addEventListener('click', () => this.updateHackerStats());
        this.refreshDefenderStatsBtn.addEventListener('click', () => this.updateDefenderStats());
        
        // System controls
        this.clearAllBtn.addEventListener('click', () => this.clearAllMessages());
        this.refreshAllBtn.addEventListener('click', () => this.refreshAll());
        this.helpBtn.addEventListener('click', () => this.showHelp());
        this.closeModalBtn.addEventListener('click', () => this.hideHelp());
        this.exportDataBtn.addEventListener('click', () => this.exportData());
        
        // Mobile navigation
        this.menuToggle.addEventListener('click', () => this.toggleMobileMenu());
        this.navClose.addEventListener('click', () => this.toggleMobileMenu());
        this.navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const panel = e.currentTarget.dataset.panel;
                this.showPanel(panel);
                this.toggleMobileMenu();
            });
        });
        
        // Logs
        this.clearLogsBtn.addEventListener('click', () => this.clearLogs());
        
        // Close modals when clicking outside
        window.addEventListener('click', (e) => {
            if (e.target === this.helpModal) {
                this.hideHelp();
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Escape key closes modals
            if (e.key === 'Escape') {
                this.hideHelp();
                if (this.mobileNav.classList.contains('active')) {
                    this.toggleMobileMenu();
                }
            }
            
            // Ctrl/Cmd + Enter sends message
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (this.currentRole === 'hacker') {
                    this.sendMessage();
                }
            }
            
            // Ctrl/Cmd + R refreshes
            if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
                e.preventDefault();
                this.refreshAll();
            }
        });
        
        // Handle window resize
        window.addEventListener('resize', () => {
            if (this.messageChart) {
                this.messageChart.resize();
            }
            if (this.defenderChart) {
                this.defenderChart.resize();
            }
            if (this.attackChart) {
                this.attackChart.resize();
            }
        });
    }
    
    async loadClientInfo() {
        try {
            const response = await fetch('/client_info');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            
            this.realIp = data.real_ip;
            this.realIpDisplay.innerHTML = `
                <i class="fas fa-network-wired"></i>
                <span>${this.realIp}</span>
            `;
            
            // Update mobile IP display
            if (this.mobileIpDisplay) {
                this.mobileIpDisplay.textContent = this.realIp;
            }
            
            // Update quick IP buttons with examples
            if (data.spoof_examples && data.spoof_examples.length > 0) {
                data.spoof_examples.forEach((example, index) => {
                    if (this.quickIpButtons[index]) {
                        this.quickIpButtons[index].dataset.ip = example.ip;
                        this.quickIpButtons[index].querySelector('.ip').textContent = example.ip;
                        this.quickIpButtons[index].querySelector('.desc').textContent = example.desc;
                    }
                });
            }
            
            console.log('✅ Client info loaded:', data);
            
        } catch (error) {
            console.error('❌ Error loading client info:', error);
            
            this.realIpDisplay.innerHTML = `
                <i class="fas fa-exclamation-triangle"></i>
                <span>Unable to detect IP</span>
            `;
            
            if (this.mobileIpDisplay) {
                this.mobileIpDisplay.textContent = 'Unknown';
            }
            
            toastr.error('Failed to load client information', '', {
                timeOut: 3000,
                closeButton: true
            });
        }
    }
    
    switchRole(role) {
        if (this.currentRole === role) return;
        
        console.log(`🔄 Switching role to: ${role}`);
        
        fetch(`/switch_role/${role}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    this.currentRole = data.role;
                    this.updateRoleUI();
                    
                    toastr.success(`Switched to ${role} role`, '', {
                        timeOut: 2000,
                        positionClass: initialData.device === 'mobile' ? 'toast-bottom-full-width' : 'toast-top-right'
                    });
                }
            })
            .catch(error => {
                console.error('❌ Error switching role:', error);
                toastr.error('Failed to switch role');
            });
    }
    
    updateRoleUI() {
        // Update button states
        this.hackerBtn.classList.remove('active');
        this.defenderBtn.classList.remove('active');
        
        if (this.currentRole === 'hacker') {
            this.hackerBtn.classList.add('active');
            this.showPanel('hacker-panel');
            this.currentPanel = 'hacker';
        } else {
            this.defenderBtn.classList.add('active');
            this.showPanel('defender-panel');
            this.currentPanel = 'defender';
        }
        
        // Update role badge in session info
        const roleBadge = document.querySelector('.role-badge');
        if (roleBadge) {
            roleBadge.className = `role-badge ${this.currentRole}`;
            roleBadge.innerHTML = `
                <i class="fas fa-${this.currentRole === 'hacker' ? 'mask' : 'shield-alt'}"></i>
                ${this.currentRole.charAt(0).toUpperCase() + this.currentRole.slice(1)}
            `;
        }
        
        // Update UI based on role
        if (this.currentRole === 'hacker') {
            this.updatePreview();
            this.updateHackerStats();
        } else {
            this.updateDefenderStats();
            this.updateTrafficStats();
        }
    }
    
    updateIpMode() {
        const useSpoofing = this.spoofMode.checked;
        
        if (useSpoofing) {
            this.spoofConfig.style.display = 'block';
            this.previewIp.textContent = this.spoofedIpInput.value || '192.168.1.100';
            this.previewIp.className = 'ip-value spoofed';
            this.previewIp.style.color = '#ff4444';
        } else {
            this.spoofConfig.style.display = 'none';
            this.previewIp.textContent = this.realIp;
            this.previewIp.className = 'ip-value legitimate';
            this.previewIp.style.color = '#44ff44';
        }
        
        this.updatePreview();
    }
    
    generateRandomIp() {
        // Generate IP in common private ranges
        const ranges = [
            () => `192.168.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 254) + 1}`,
            () => `10.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 254) + 1}`,
            () => `172.${Math.floor(Math.random() * 16) + 16}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 254) + 1}`
        ];
        
        const randomRange = ranges[Math.floor(Math.random() * ranges.length)];
        const newIp = randomRange();
        
        this.spoofedIpInput.value = newIp;
        this.updatePreview();
        this.validateCurrentIp();
        
        toastr.info(`Generated random IP: ${newIp}`);
    }
    
    validateCurrentIp() {
        const ip = this.spoofedIpInput.value.trim();
        
        if (!ip) {
            this.ipValidation.innerHTML = '<span style="color: #ffaa00;">Please enter an IP address</span>';
            return false;
        }
        
        if (!this.validateIp(ip)) {
            this.ipValidation.innerHTML = '<span style="color: #ff4444;">Invalid IP address format</span>';
            return false;
        }
        
        // Check if it's a private IP (common in spoofing)
        const isPrivate = this.isPrivateIp(ip);
        
        if (isPrivate) {
            this.ipValidation.innerHTML = `
                <span style="color: #44ff44;">✅ Valid private IP</span>
                <br><small style="color: #cccccc;">Commonly used in spoofing attacks</small>
            `;
        } else {
            this.ipValidation.innerHTML = `
                <span style="color: #44ff44;">✅ Valid public IP</span>
                <br><small style="color: #cccccc;">Could be spoofed from external networks</small>
            `;
        }
        
        return true;
    }
    
    validateIp(ip) {
        const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        
        if (!ipPattern.test(ip)) {
            return false;
        }
        
        const parts = ip.split('.');
        for (let part of parts) {
            const num = parseInt(part, 10);
            if (num < 0 || num > 255 || isNaN(num)) {
                return false;
            }
        }
        
        // Check for reserved addresses
        if (parts[0] === '0') return false;
        if (parts[0] === '127') return false;
        if (parts[0] === '255' && parts[1] === '255' && parts[2] === '255' && parts[3] === '255') return false;
        
        return true;
    }
    
    isPrivateIp(ip) {
        const parts = ip.split('.');
        const first = parseInt(parts[0], 10);
        const second = parseInt(parts[1], 10);
        
        // 10.0.0.0 - 10.255.255.255
        if (first === 10) return true;
        
        // 172.16.0.0 - 172.31.255.255
        if (first === 172 && second >= 16 && second <= 31) return true;
        
        // 192.168.0.0 - 192.168.255.255
        if (first === 192 && second === 168) return true;
        
        // 169.254.0.0 - 169.254.255.255 (link-local)
        if (first === 169 && second === 254) return true;
        
        return false;
    }
    
    applyTemplate(template) {
        const templates = {
            normal: "Hello, this is a normal message from the network administrator. Please ensure all systems are updated with the latest security patches.",
            phishing: "URGENT: Your account security has been compromised! Click http://verify-account-now.com to reset your password immediately. This link will expire in 15 minutes.",
            attack: "Initiating distributed denial-of-service attack from multiple spoofed sources... Target: web-server-01. Attack vectors: SYN flood, HTTP GET flood, UDP amplification."
        };
        
        const message = templates[template] || templates.normal;
        this.hackerMessage.value = message;
        this.updatePreview();
        this.updateCharCount();
        
        toastr.info(`Applied ${template} template`);
    }
    
    updateCharCount() {
        const count = this.hackerMessage.value.length;
        this.charCount.textContent = count;
        
        if (count > 450) {
            this.charCount.style.color = '#ff4444';
        } else if (count > 400) {
            this.charCount.style.color = '#ffaa00';
        } else {
            this.charCount.style.color = '#cccccc';
        }
    }
    
    updatePreview() {
        const message = this.hackerMessage.value;
        const useSpoofing = this.spoofMode.checked;
        const ip = useSpoofing ? (this.spoofedIpInput.value || '192.168.1.100') : this.realIp;
        
        // Update IP preview
        this.previewIp.textContent = ip;
        
        if (useSpoofing) {
            this.previewIp.className = 'ip-value spoofed';
            this.previewIp.style.color = '#ff4444';
        } else {
            this.previewIp.className = 'ip-value legitimate';
            this.previewIp.style.color = '#44ff44';
        }
        
        // Update message preview
        if (message) {
            const preview = message.length > 80 ? 
                message.substring(0, 80) + '...' : message;
            this.previewMessage.textContent = preview;
        } else {
            this.previewMessage.textContent = '[Type your message above]';
        }
    }
    
    sendMessage() {
        const message = this.hackerMessage.value.trim();
        
        if (!message) {
            toastr.warning('Please enter a message');
            this.hackerMessage.focus();
            return;
        }
        
        const useSpoofing = this.spoofMode.checked;
        let spoofedIp = this.spoofedIpInput.value.trim();
        
        if (useSpoofing) {
            if (!spoofedIp) {
                toastr.warning('Please enter a spoofed IP address');
                this.spoofedIpInput.focus();
                return;
            }
            
            if (!this.validateIp(spoofedIp)) {
                toastr.error('Invalid IP address format. Example: 192.168.1.100');
                this.spoofedIpInput.focus();
                return;
            }
        } else {
            spoofedIp = this.realIp;
        }
        
        // Disable send button during sending
        const originalText = this.sendMessageBtn.innerHTML;
        this.sendMessageBtn.disabled = true;
        this.sendMessageBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> SENDING...';
        
        // Send via WebSocket
        this.socket.emit('send_message', {
            message: message,
            spoofed_ip: spoofedIp,
            use_spoofing: useSpoofing,
            attack_type: 'manual'
        });
        
        // Re-enable button after 2 seconds
        setTimeout(() => {
            this.sendMessageBtn.disabled = false;
            this.sendMessageBtn.innerHTML = originalText;
        }, 2000);
    }
    
    simulateAttack(type) {
        console.log(`🎮 Simulating attack: ${type}`);
        
        // Show loading state
        const button = document.querySelector(`.simulate-btn[data-type="${type}"]`);
        if (button) {
            const originalHTML = button.innerHTML;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Loading...</span>';
            button.disabled = true;
            
            setTimeout(() => {
                button.innerHTML = originalHTML;
                button.disabled = false;
            }, 3000);
        }
        
        this.socket.emit('simulate_attack', { type: type });
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
        div.dataset.analyzed = message.detection_guess ? 'true' : 'false';
        
        const time = message.timestamp_display || 
            new Date(message.timestamp).toLocaleTimeString([], { 
                hour: '2-digit', 
                minute: '2-digit',
                second: '2-digit'
            });
        
        const messagePreview = message.message.length > 60 ? 
            message.message.substring(0, 60) + '...' : message.message;
        
        // Status icon and color
        let statusIcon, statusColor, statusText;
        
        if (message.detection_guess) {
            if (message.detection_correct) {
                statusIcon = 'fas fa-check-circle';
                statusColor = '#44ff44';
                statusText = 'Correct';
            } else {
                statusIcon = 'fas fa-times-circle';
                statusColor = '#ff4444';
                statusText = 'Incorrect';
            }
        } else if (message.is_spoofed) {
            statusIcon = 'fas fa-user-secret';
            statusColor = '#ff4444';
            statusText = 'Suspicious';
        } else {
            statusIcon = 'fas fa-user-check';
            statusColor = '#44ff44';
            statusText = 'Legitimate';
        }
        
        div.innerHTML = `
            <div class="ip-address ${message.is_spoofed ? 'spoofed' : 'legitimate'}">
                <i class="${message.is_spoofed ? 'fas fa-user-secret' : 'fas fa-user-check'}"></i>
                ${message.displayed_ip}
            </div>
            <div class="time">${time}</div>
            <div class="status">
                <i class="${statusIcon}" style="color: ${statusColor}"></i>
                ${statusText}
            </div>
        `;
        
        // Add click event for analysis
        div.addEventListener('click', () => {
            this.selectMessageForAnalysis(message);
        });
        
        return div;
    }
    
    selectMessageForAnalysis(message) {
        if (message.detection_guess) {
            toastr.info('This message has already been analyzed');
            return;
        }
        
        this.selectedMessageId = message.id;
        
        // Highlight selected message
        document.querySelectorAll('.message-item').forEach(item => {
            item.classList.remove('selected');
        });
        
        const selectedItem = document.querySelector(`.message-item[data-id="${message.id}"]`);
        if (selectedItem) {
            selectedItem.classList.add('selected');
        }
        
        // Show analysis card
        this.analysisCard.style.display = 'block';
        this.resultCard.style.display = 'none';
        
        // Hide analysis card on mobile after selection
        if (initialData.device === 'mobile') {
            setTimeout(() => {
                this.analysisCard.scrollIntoView({ behavior: 'smooth' });
            }, 100);
        }
        
        // Display message details
        const time = new Date(message.timestamp).toLocaleTimeString([], { 
            hour: '2-digit', 
            minute: '2-digit',
            second: '2-digit'
        });
        
        const date = new Date(message.timestamp).toLocaleDateString();
        
        this.selectedMessageDetails.innerHTML = `
            <div class="message-analysis-details">
                <div class="detail-item">
                    <span class="detail-label">Sender IP:</span>
                    <span class="detail-value ip ${message.is_spoofed ? 'spoofed' : 'legitimate'}">
                        ${message.displayed_ip}
                        ${message.is_spoofed ? ' <i class="fas fa-user-secret"></i>' : ' <i class="fas fa-user-check"></i>'}
                    </span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Time:</span>
                    <span class="detail-value">${date} ${time}</span>
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
                ${message.device ? `
                    <div class="detail-item">
                        <span class="detail-label">Sent from:</span>
                        <span class="detail-value">${message.device === 'mobile' ? '📱 Mobile' : '💻 Desktop'}</span>
                    </div>
                ` : ''}
            </div>
        `;
        
        // Reset guess buttons and slider
        this.legitGuessBtn.classList.remove('active');
        this.spoofGuessBtn.classList.remove('active');
        this.confidenceSlider.value = 50;
        this.confidenceValue.textContent = '50';
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
            toastr.warning('Please select "Legitimate IP" or "Spoofed IP"');
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
    
    skipAnalysis() {
        this.closeAnalysis();
        toastr.info('Skipped analysis');
    }
    
    showAnalysisResult(result) {
        // Re-enable submit button
        this.submitAnalysisBtn.disabled = false;
        this.submitAnalysisBtn.innerHTML = '<i class="fas fa-check-circle"></i> ANALYZE MESSAGE';
        
        // Show result card
        this.resultCard.style.display = 'block';
        this.analysisCard.style.display = 'none';
        
        // Scroll to results on mobile
        if (initialData.device === 'mobile') {
            setTimeout(() => {
                this.resultCard.scrollIntoView({ behavior: 'smooth' });
            }, 100);
        }
        
        const resultClass = result.is_correct ? 'correct' : 'incorrect';
        const resultIcon = result.is_correct ? 'fa-check-circle' : 'fa-times-circle';
        const resultText = result.is_correct ? 'CORRECT ANALYSIS!' : 'INCORRECT ANALYSIS';
        const resultColor = result.is_correct ? '#44ff44' : '#ff4444';
        
        this.resultContent.innerHTML = `
            <div class="result-header ${resultClass}">
                <i class="fas ${resultIcon}" style="color: ${resultColor}; font-size: 2.5rem;"></i>
                <h3 style="color: ${resultColor};">${resultText}</h3>
            </div>
            
            <div class="result-summary">
                <p>You guessed: <strong>${result.your_guess.toUpperCase()}</strong></p>
                <p>Actual status: <strong>${result.actual_status.toUpperCase()}</strong></p>
                <p>Confidence: <strong>${result.confidence}%</strong></p>
            </div>
            
            <div class="result-details">
                <div class="result-item">
                    <span class="result-label">Real IP:</span>
                    <span class="result-value ip">${result.real_ip}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Displayed IP:</span>
                    <span class="result-value ip">${result.displayed_ip}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Your Guess:</span>
                    <span class="result-value">${result.your_guess.toUpperCase()}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Actual Status:</span>
                    <span class="result-value">${result.actual_status.toUpperCase()}</span>
                </div>
            </div>
            
            <div class="result-hints">
                <h5><i class="fas fa-lightbulb"></i> Analysis Hints:</h5>
                <ul>
                    ${result.hints.map(hint => `<li>${this.escapeHtml(hint)}</li>`).join('')}
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
                        <div class="stat-number">${result.user_stats.incorrect}</div>
                        <div class="stat-label">Incorrect</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">${result.user_stats.total_analyzed}</div>
                        <div class="stat-label">Total Analyzed</div>
                    </div>
                </div>
            </div>
            
            <div class="result-actions">
                <button class="btn-secondary" id="analyze-another">
                    <i class="fas fa-search"></i> Analyze Another
                </button>
                <button class="btn-secondary" id="view-stats">
                    <i class="fas fa-chart-bar"></i> View Stats
                </button>
            </div>
        `;
        
        // Add event listeners to result actions
        document.getElementById('analyze-another').addEventListener('click', () => {
            this.closeResult();
            this.closeAnalysis();
        });
        
        document.getElementById('view-stats').addEventListener('click', () => {
            this.showPanel('stats-panel');
            this.closeResult();
        });
    }
    
    closeAnalysis() {
        this.analysisCard.style.display = 'none';
        this.selectedMessageId = null;
        
        // Clear selection
        document.querySelectorAll('.message-item').forEach(item => {
            item.classList.remove('selected');
        });
    }
    
    closeResult() {
        this.resultCard.style.display = 'none';
        this.closeAnalysis();
    }
    
    filterMessages() {
        const filter = this.trafficFilter.value;
        const messages = this.messagesList.querySelectorAll('.message-item');
        
        let visibleCount = 0;
        
        messages.forEach(message => {
            const isSpoofed = message.dataset.spoofed === 'true';
            const isAnalyzed = message.dataset.analyzed === 'true';
            
            let shouldShow = true;
            
            switch(filter) {
                case 'all':
                    shouldShow = true;
                    break;
                case 'spoofed':
                    shouldShow = isSpoofed;
                    break;
                case 'legitimate':
                    shouldShow = !isSpoofed;
                    break;
                case 'unanalyzed':
                    shouldShow = !isAnalyzed;
                    break;
            }
            
            message.style.display = shouldShow ? 'grid' : 'none';
            if (shouldShow) visibleCount++;
        });
        
        // Show empty state if no messages visible
        if (visibleCount === 0) {
            this.showEmptyState();
        }
    }
    
    showEmptyState() {
        this.messagesList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-envelope-open-text"></i>
                <h4>No messages yet</h4>
                <p>Messages will appear here when hackers send them</p>
                <p class="hint">Each message shows the sender's IP address</p>
                <button class="btn-secondary" id="refresh-traffic-btn" style="margin-top: 1rem;">
                    <i class="fas fa-sync-alt"></i> Refresh
                </button>
            </div>
        `;
        
        document.getElementById('refresh-traffic-btn').addEventListener('click', () => {
            this.refreshTraffic();
        });
    }
    
    refreshTraffic() {
        this.socket.emit('request_history');
        toastr.info('Refreshing traffic...');
    }
    
    updateMessageStatus(messageItem, analysisData) {
        const statusElement = messageItem.querySelector('.status');
        
        if (analysisData.detection_correct) {
            statusElement.innerHTML = `
                <i class="fas fa-check-circle" style="color: #44ff44;"></i>
                Correct
            `;
            statusElement.style.color = '#44ff44';
        } else {
            statusElement.innerHTML = `
                <i class="fas fa-times-circle" style="color: #ff4444;"></i>
                Incorrect
            `;
            statusElement.style.color = '#ff4444';
        }
        
        messageItem.dataset.analyzed = 'true';
    }
    
    updateTrafficStats() {
        const messages = this.messagesList.querySelectorAll('.message-item');
        const total = messages.length;
        const suspicious = Array.from(messages).filter(msg => msg.dataset.spoofed === 'true').length;
        const analyzed = Array.from(messages).filter(msg => msg.dataset.analyzed === 'true').length;
        
        this.totalMessagesCount.textContent = total;
        this.suspiciousCount.textContent = suspicious;
        this.analyzedCount.textContent = analyzed;
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
            console.error('❌ Error updating hacker stats:', error);
        }
    }
    
    async updateDefenderStats() {
        try {
            const response = await fetch('/stats');
            const data = await response.json();
            
            this.totalAnalyzed.textContent = data.correct_detections || 0;
            
            // Calculate accuracy
            const totalAnalyzed = data.correct_detections || 0;
            const accuracy = data.total_messages > 0 ? 
                Math.round((data.correct_detections / data.total_messages) * 100) : 0;
                
            this.detectionAccuracy.textContent = `${accuracy}%`;
            
            // Update defender chart
            if (this.defenderChart) {
                this.updateDefenderChart(data);
            }
            
        } catch (error) {
            console.error('❌ Error updating defender stats:', error);
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
            this.activeConnections.textContent = data.active_connections;
            
            // Update detection rate
            const detectionRate = data.total_messages > 0 ? 
                Math.round((data.correct_detections / data.total_messages) * 100) : 0;
            this.detectionRate.textContent = `${detectionRate}%`;
            
            // Update top spoofed IPs
            if (data.top_spoofed_ips && data.top_spoofed_ips.length > 0) {
                this.topSpoofedIps.innerHTML = data.top_spoofed_ips.map((ip, index) => `
                    <div class="top-ip-item">
                        <span class="ip-rank">${index + 1}</span>
                        <span class="ip-address">${ip.ip}</span>
                        <span class="ip-count">${ip.count}x</span>
                    </div>
                `).join('');
            }
            
            // Update activity timeline
            if (data.recent_activity && data.recent_activity.length > 0) {
                this.activityTimeline.innerHTML = data.recent_activity.map(activity => `
                    <div class="activity-item">
                        <span class="activity-time">${activity.time}</span>
                        <span class="activity-desc">${activity.count} messages</span>
                    </div>
                `).join('');
            }
            
            // Update charts
            if (this.attackChart) {
                this.updateAttackChart(data);
            }
            
        } catch (error) {
            console.error('❌ Error updating system stats:', error);
        }
    }
    
    updateAllStats() {
        this.updateHackerStats();
        this.updateDefenderStats();
        this.updateSystemStats();
    }
    
    initCharts() {
        // Initialize attack chart
        const attackCtx = document.getElementById('attack-chart');
        if (attackCtx) {
            this.attackChart = new Chart(attackCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Legitimate', 'Spoofed', 'Detected'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: [
                            'rgba(68, 255, 68, 0.8)',
                            'rgba(255, 68, 68, 0.8)',
                            'rgba(68, 119, 255, 0.8)'
                        ],
                        borderColor: [
                            'rgba(68, 255, 68, 1)',
                            'rgba(255, 68, 68, 1)',
                            'rgba(68, 119, 255, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#ffffff',
                                font: {
                                    size: 12
                                },
                                padding: 15
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleColor: '#ffffff',
                            bodyColor: '#ffffff',
                            padding: 10
                        }
                    }
                }
            });
        }
        
        // Initialize defender chart
        const defenderCtx = document.getElementById('defender-chart');
        if (defenderCtx) {
            this.defenderChart = new Chart(defenderCtx, {
                type: 'bar',
                data: {
                    labels: ['Correct', 'Incorrect', 'Accuracy'],
                    datasets: [{
                        label: 'Performance',
                        data: [0, 0, 0],
                        backgroundColor: [
                            'rgba(68, 255, 68, 0.8)',
                            'rgba(255, 68, 68, 0.8)',
                            'rgba(68, 119, 255, 0.8)'
                        ],
                        borderColor: [
                            'rgba(68, 255, 68, 1)',
                            'rgba(255, 68, 68, 1)',
                            'rgba(68, 119, 255, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100,
                            ticks: {
                                color: '#ffffff'
                            },
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            }
                        },
                        x: {
                            ticks: {
                                color: '#ffffff'
                            },
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
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
    }
    
    updateAttackChart(data) {
        if (this.attackChart) {
            this.attackChart.data.datasets[0].data = [
                data.legitimate_messages,
                data.spoofed_messages,
                data.correct_detections
            ];
            this.attackChart.update();
        }
    }
    
    updateDefenderChart(data) {
        if (this.defenderChart) {
            const accuracy = data.total_messages > 0 ? 
                Math.round((data.correct_detections / data.total_messages) * 100) : 0;
                
            this.defenderChart.data.datasets[0].data = [
                data.correct_detections || 0,
                (data.total_messages - data.correct_detections) || 0,
                accuracy
            ];
            this.defenderChart.update();
        }
    }
    
    async clearAllMessages() {
        if (!confirm('Are you sure you want to clear ALL messages and statistics? This cannot be undone.')) {
            return;
        }
        
        try {
            const response = await fetch('/clear_all', {
                method: 'POST'
            });
            
            if (response.ok) {
                // The socket event will handle the UI update
                this.socket.emit('request_history');
                toastr.success('All data cleared successfully');
            } else {
                throw new Error('Server returned an error');
            }
        } catch (error) {
            console.error('❌ Error clearing messages:', error);
            toastr.error('Failed to clear messages');
        }
    }
    
    async refreshAll() {
        toastr.info('Refreshing all data...');
        
        await this.loadClientInfo();
        await this.updateAllStats();
        
        if (this.currentRole === 'hacker') {
            await this.updateHackerStats();
        } else {
            await this.updateDefenderStats();
            this.refreshTraffic();
        }
        
        toastr.success('Data refreshed successfully');
    }
    
    showHelp() {
        this.helpModal.style.display = 'flex';
        this.helpModal.classList.add('active');
        
        // Prevent body scrolling
        document.body.style.overflow = 'hidden';
    }
    
    hideHelp() {
        this.helpModal.style.display = 'none';
        this.helpModal.classList.remove('active');
        
        // Restore body scrolling
        document.body.style.overflow = '';
    }
    
    toggleMobileMenu() {
        this.mobileNav.classList.toggle('active');
        
        // Toggle body scrolling
        if (this.mobileNav.classList.contains('active')) {
            document.body.style.overflow = 'hidden';
        } else {
            document.body.style.overflow = '';
        }
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
            this.currentPanel = panelId;
            
            // Update active nav item
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            
            const navItem = document.querySelector(`.nav-item[data-panel="${panelId.replace('-panel', '')}"]`);
            if (navItem) {
                navItem.classList.add('active');
            }
        }
    }
    
    showNotification(title, message) {
        // Check if browser supports notifications
        if (!("Notification" in window)) {
            return;
        }
        
        // Check if permission is already granted
        if (Notification.permission === "granted") {
            const notification = new Notification(title, {
                body: message,
                icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🎭</text></svg>'
            });
            
            // Close notification after 5 seconds
            setTimeout(() => {
                notification.close();
            }, 5000);
        }
        // Otherwise, ask for permission
        else if (Notification.permission !== "denied") {
            Notification.requestPermission().then(permission => {
                if (permission === "granted") {
                    this.showNotification(title, message);
                }
            });
        }
    }
    
    updateConnectionsCount(count) {
        if (this.connectionsCount) {
            this.connectionsCount.textContent = `${count} online`;
        }
    }
    
    startBackgroundTasks() {
        // Update server time every second
        setInterval(() => {
            const now = new Date();
            this.serverTime.textContent = now.toLocaleTimeString([], { 
                hour: '2-digit', 
                minute: '2-digit',
                second: '2-digit'
            });
            
            // Update uptime
            const uptime = Math.floor((Date.now() - this.connectionStartTime) / 1000);
            const hours = Math.floor(uptime / 3600);
            const minutes = Math.floor((uptime % 3600) / 60);
            const seconds = uptime % 60;
            
            if (hours > 0) {
                this.serverUptime.textContent = `Uptime: ${hours}h ${minutes}m`;
            } else if (minutes > 0) {
                this.serverUptime.textContent = `Uptime: ${minutes}m ${seconds}s`;
            } else {
                this.serverUptime.textContent = `Uptime: ${seconds}s`;
            }
        }, 1000);
        
        // Ping server every 30 seconds to keep connection alive
        setInterval(() => {
            if (this.socket && this.socket.connected) {
                this.socket.emit('ping');
            }
        }, 30000);
        
        // Auto-refresh stats every 10 seconds
        setInterval(() => {
            this.updateAllStats();
        }, 10000);
    }
    
    async exportData() {
        try {
            const response = await fetch('/export_data');
            const data = await response.json();
            
            // Create a downloadable JSON file
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ip-spoofing-lab-export-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            toastr.success('Data exported successfully');
        } catch (error) {
            console.error('❌ Error exporting data:', error);
            toastr.error('Failed to export data');
        }
    }
    
    async clearLogs() {
        if (!confirm('Are you sure you want to clear all attack logs?')) {
            return;
        }
        
        // Clear logs from UI
        this.logsList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-clipboard"></i>
                <h4>No attack logs yet</h4>
                <p>Attack logs will appear here when spoofed messages are sent</p>
            </div>
        `;
        
        // Reset log counters
        this.totalLogs.textContent = '0';
        this.ddosLogs.textContent = '0';
        this.phishingLogs.textContent = '0';
        this.mitmLogs.textContent = '0';
        
        toastr.success('Attack logs cleared');
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    // Check for service worker support
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js').catch(error => {
            console.log('Service Worker registration failed:', error);
        });
    }
    
    // Initialize the lab
    window.spoofingLab = new RealTimeSpoofingLab();
    
    // Handle page visibility changes
    document.addEventListener('visibilitychange', () => {
        if (window.spoofingLab && window.spoofingLab.socket) {
            if (document.hidden) {
                // Page is hidden, reduce activity
                console.log('Page hidden');
            } else {
                // Page is visible, refresh data
                console.log('Page visible, refreshing...');
                window.spoofingLab.refreshAll();
            }
        }
    });
});
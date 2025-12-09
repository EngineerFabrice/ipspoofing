#!/usr/bin/env python3
"""
Real-Time IP Spoofing Attack & Defense Lab
Educational tool for demonstrating IP spoofing attacks and detection methods
"""

from flask import Flask, render_template, request, jsonify, session, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import sqlite3
from datetime import datetime
import random
import hashlib
import time
import json
import os
from werkzeug.middleware.proxy_fix import ProxyFix

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Add proxy support for real IP detection
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Initialize Socket.IO
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    logger=True,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25
)

CORS(app)

# Global storage
active_connections = {}
message_history = []
attack_logs = []

# Database initialization
def init_db():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect('messages.db', check_same_thread=False)
    c = conn.cursor()
    
    # Messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  session_id TEXT,
                  role TEXT,
                  real_ip TEXT,
                  spoofed_ip TEXT,
                  displayed_ip TEXT,
                  is_spoofed INTEGER DEFAULT 0,
                  message TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  detection_guess TEXT,
                  detection_correct INTEGER,
                  confidence INTEGER,
                  device TEXT,
                  attack_type TEXT)''')
    
    # Statistics table
    c.execute('''CREATE TABLE IF NOT EXISTS statistics
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  total_messages INTEGER DEFAULT 0,
                  spoofed_messages INTEGER DEFAULT 0,
                  detected_messages INTEGER DEFAULT 0,
                  active_connections INTEGER DEFAULT 0)''')
    
    # Attacks table
    c.execute('''CREATE TABLE IF NOT EXISTS attacks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  attack_type TEXT,
                  source_ip TEXT,
                  target_ip TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  duration INTEGER,
                  success INTEGER)''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

init_db()

def get_real_ip(request):
    """Extract real IP address from request, handling proxies"""
    if request.headers.get('X-Forwarded-For'):
        # Handle proxy servers
        ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
    else:
        ip = request.remote_addr
    
    # Localhost handling
    if ip == '127.0.0.1' or ip.startswith('192.168') or ip.startswith('10.'):
        # For local testing, generate a more realistic IP
        ip = f"192.168.{random.randint(1, 255)}.{random.randint(2, 254)}"
    
    return ip

def generate_spoofed_ips():
    """Generate realistic spoofed IP examples"""
    return [
        {"ip": "192.168.1.100", "desc": "Common internal device", "type": "internal"},
        {"ip": "10.0.0.50", "desc": "Network server", "type": "internal"},
        {"ip": "172.16.0.25", "desc": "Another subnet", "type": "internal"},
        {"ip": "8.8.8.8", "desc": "Google DNS server", "type": "external"},
        {"ip": "1.1.1.1", "desc": "Cloudflare DNS", "type": "external"},
        {"ip": f"203.0.{random.randint(0,255)}.{random.randint(1,254)}", "desc": "Random public IP", "type": "external"},
        {"ip": f"172.31.{random.randint(0,255)}.{random.randint(1,254)}", "desc": "AWS internal IP", "type": "cloud"}
    ]

def validate_ip(ip):
    """Validate IP address format"""
    import re
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    if not re.match(pattern, ip):
        return False
    
    octets = ip.split('.')
    for octet in octets:
        num = int(octet)
        if num < 0 or num > 255:
            return False
    
    return True

def is_internal_ip(ip):
    """Check if IP is in private/internal ranges"""
    octets = list(map(int, ip.split('.')))
    
    # 10.0.0.0 - 10.255.255.255
    if octets[0] == 10:
        return True
    
    # 172.16.0.0 - 172.31.255.255
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    
    # 192.168.0.0 - 192.168.255.255
    if octets[0] == 192 and octets[1] == 168:
        return True
    
    # 169.254.0.0 - 169.254.255.255 (link-local)
    if octets[0] == 169 and octets[1] == 254:
        return True
    
    return False

@app.route('/')
def index():
    """Main page - auto-detects device type and assigns role"""
    # Generate unique session ID
    if 'session_id' not in session:
        session['session_id'] = hashlib.md5(
            f"{datetime.now()}{random.random()}".encode()
        ).hexdigest()[:12]
        session.permanent = True
    
    # Detect device type and assign role
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Default role based on device
    if any(x in user_agent for x in ['mobile', 'android', 'iphone', 'ipad', 'tablet']):
        default_role = 'defender'
        device = 'mobile'
    else:
        default_role = 'hacker'
        device = 'desktop'
    
    # Store device type in session
    if 'device' not in session:
        session['device'] = device
    if 'role' not in session:
        session['role'] = default_role
    
    # Log connection
    real_ip = get_real_ip(request)
    print(f"🔗 New connection: {session['session_id']} ({device}) as {session['role']} from {real_ip}")
    
    return render_template('index.html',
                         session_id=session['session_id'],
                         role=session['role'],
                         device=device,
                         real_ip=real_ip)

@app.route('/switch_role/<role>')
def switch_role(role):
    """Switch between hacker and defender roles"""
    if role in ['hacker', 'defender']:
        session['role'] = role
        
        # Update active connections
        for sid, data in active_connections.items():
            if data.get('session_id') == session.get('session_id'):
                data['role'] = role
                break
        
        socketio.emit('role_switched', {
            'session_id': session.get('session_id'),
            'role': role
        }, broadcast=True)
        
        return jsonify({'status': 'success', 'role': role})
    return jsonify({'status': 'error', 'message': 'Invalid role'})

@app.route('/client_info')
def client_info():
    """Get client information including real IP"""
    real_ip = get_real_ip(request)
    
    return jsonify({
        'real_ip': real_ip,
        'session_id': session.get('session_id'),
        'role': session.get('role'),
        'device': session.get('device'),
        'spoof_examples': generate_spoofed_ips(),
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })

@app.route('/stats')
def get_stats():
    """Get comprehensive statistics"""
    conn = sqlite3.connect('messages.db', check_same_thread=False)
    c = conn.cursor()
    
    # Overall statistics
    c.execute('''SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN is_spoofed = 1 THEN 1 ELSE 0 END) as spoofed,
                    SUM(CASE WHEN detection_correct = 1 THEN 1 ELSE 0 END) as correct
                 FROM messages''')
    stats = c.fetchone()
    
    # Role distribution
    c.execute('''SELECT role, COUNT(*) as count 
                 FROM messages 
                 WHERE role IS NOT NULL
                 GROUP BY role''')
    role_stats = c.fetchall()
    
    # Top spoofed IPs
    c.execute('''SELECT displayed_ip, COUNT(*) as count 
                 FROM messages 
                 WHERE is_spoofed = 1 
                 GROUP BY displayed_ip 
                 ORDER BY count DESC 
                 LIMIT 10''')
    top_spoofed = c.fetchall()
    
    # Recent activity
    c.execute('''SELECT 
                    strftime('%H:%M', timestamp) as time,
                    COUNT(*) as count
                 FROM messages 
                 WHERE timestamp > datetime('now', '-1 hour')
                 GROUP BY strftime('%H:%M', timestamp)
                 ORDER BY time DESC
                 LIMIT 10''')
    recent_activity = c.fetchall()
    
    conn.close()
    
    return jsonify({
        'total_messages': stats[0] or 0,
        'spoofed_messages': stats[1] or 0,
        'legitimate_messages': (stats[0] or 0) - (stats[1] or 0),
        'correct_detections': stats[2] or 0,
        'role_distribution': {role: count for role, count in role_stats},
        'top_spoofed_ips': [{"ip": ip, "count": count} for ip, count in top_spoofed],
        'spoofing_rate': round((stats[1] or 0) / (stats[0] or 1) * 100, 1),
        'detection_rate': round((stats[2] or 0) / (stats[0] or 1) * 100, 1) if stats[0] else 0,
        'recent_activity': [{"time": time, "count": count} for time, count in recent_activity],
        'active_connections': len(active_connections),
        'server_time': datetime.now().strftime('%H:%M:%S')
    })

@app.route('/attack_logs')
def get_attack_logs():
    """Get recent attack logs"""
    return jsonify({
        'logs': attack_logs[-20:],  # Last 20 logs
        'total': len(attack_logs)
    })

@app.route('/clear_all', methods=['POST'])
def clear_all():
    """Clear all messages and reset statistics"""
    try:
        conn = sqlite3.connect('messages.db', check_same_thread=False)
        c = conn.cursor()
        
        # Clear messages but keep structure
        c.execute('DELETE FROM messages')
        
        # Reset statistics
        c.execute('DELETE FROM statistics')
        
        conn.commit()
        conn.close()
        
        # Clear in-memory storage
        message_history.clear()
        attack_logs.clear()
        
        # Notify all clients
        socketio.emit('all_cleared', {
            'message': 'All messages and statistics cleared',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, broadcast=True)
        
        return jsonify({'status': 'success', 'message': 'All data cleared'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/export_data')
def export_data():
    """Export all data as JSON"""
    conn = sqlite3.connect('messages.db', check_same_thread=False)
    c = conn.cursor()
    
    c.execute('SELECT * FROM messages ORDER BY timestamp DESC')
    messages = [dict(zip([column[0] for column in c.description], row)) 
                for row in c.fetchall()]
    
    conn.close()
    
    return jsonify({
        'export_time': datetime.now().isoformat(),
        'total_messages': len(messages),
        'messages': messages
    })

# Socket.IO Event Handlers
@socketio.on('connect')
def handle_connect():
    """Handle new client connection"""
    session_id = request.sid
    real_ip = get_real_ip(request)
    
    # Store connection info
    active_connections[session_id] = {
        'session_id': session.get('session_id'),
        'role': session.get('role', 'hacker'),
        'device': session.get('device', 'desktop'),
        'real_ip': real_ip,
        'connected_at': time.time(),
        'last_activity': time.time()
    }
    
    print(f"✅ New connection: {session_id} ({session.get('device')}) as {session.get('role')}")
    
    # Send welcome message
    emit('connection_established', {
        'session_id': session_id,
        'role': session.get('role'),
        'device': session.get('device'),
        'real_ip': real_ip,
        'active_connections': len(active_connections),
        'message': 'Connected to IP Spoofing Lab',
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })
    
    # Broadcast updated connection count
    socketio.emit('connections_updated', {
        'count': len(active_connections),
        'connections': list(active_connections.values())
    }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    session_id = request.sid
    
    if session_id in active_connections:
        role = active_connections[session_id]['role']
        device = active_connections[session_id]['device']
        del active_connections[session_id]
        
        print(f"❌ Disconnected: {session_id} ({device}) as {role}")
        
        # Broadcast updated connection count
        socketio.emit('connections_updated', {
            'count': len(active_connections),
            'connections': list(active_connections.values())
        }, broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    """Handle sending a new message"""
    try:
        session_id = request.sid
        message = data.get('message', '').strip()
        spoofed_ip = data.get('spoofed_ip', '').strip()
        use_spoofing = data.get('use_spoofing', False)
        attack_type = data.get('attack_type', 'normal')
        
        if not message:
            emit('error', {'message': 'Message cannot be empty'})
            return
        
        real_ip = active_connections.get(session_id, {}).get('real_ip', get_real_ip(request))
        
        # Validate spoofed IP if used
        if use_spoofing and spoofed_ip:
            if not validate_ip(spoofed_ip):
                emit('error', {'message': 'Invalid IP address format. Use: 192.168.1.100'})
                return
            displayed_ip = spoofed_ip
            is_spoofed = 1
            
            # Log attack
            attack_log = {
                'type': 'ip_spoofing',
                'real_ip': real_ip,
                'spoofed_ip': spoofed_ip,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'message': message[:100]
            }
            attack_logs.append(attack_log)
        else:
            displayed_ip = real_ip
            is_spoofed = 0
            spoofed_ip = real_ip
        
        # Get role from active connections
        role = active_connections.get(session_id, {}).get('role', 'hacker')
        device = active_connections.get(session_id, {}).get('device', 'desktop')
        
        # Store in database
        conn = sqlite3.connect('messages.db', check_same_thread=False)
        c = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        c.execute('''INSERT INTO messages 
                     (session_id, role, real_ip, spoofed_ip, displayed_ip, 
                      is_spoofed, message, timestamp, device, attack_type) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (session_id, role, real_ip, spoofed_ip, displayed_ip,
                   is_spoofed, message, timestamp, device, attack_type))
        
        message_id = c.lastrowid
        
        # Update statistics
        c.execute('''INSERT INTO statistics 
                     (total_messages, spoofed_messages, active_connections)
                     VALUES (1, ?, ?)''',
                  (is_spoofed, len(active_connections)))
        
        conn.commit()
        
        # Get the inserted message
        c.execute('SELECT * FROM messages WHERE id = ?', (message_id,))
        msg = c.fetchone()
        conn.close()
        
        # Create message object
        columns = ['id', 'session_id', 'role', 'real_ip', 'spoofed_ip', 
                  'displayed_ip', 'is_spoofed', 'message', 'timestamp', 
                  'detection_guess', 'detection_correct', 'confidence', 'device', 'attack_type']
        
        message_obj = dict(zip(columns, msg))
        message_obj['timestamp_display'] = datetime.now().strftime('%H:%M:%S')
        
        # Add to history
        message_history.append(message_obj)
        if len(message_history) > 100:
            message_history.pop(0)
        
        # Log to console
        status = "🎭 SPOOFED" if is_spoofed else "✅ LEGITIMATE"
        print(f"\n{status} MESSAGE")
        print(f"   From: {role.upper()} ({device})")
        print(f"   Real IP: {real_ip}")
        print(f"   Displayed IP: {displayed_ip}")
        print(f"   Message: {message[:50]}...")
        
        # Broadcast to ALL clients
        socketio.emit('new_message', message_obj, broadcast=True)
        print(f"   📢 Broadcasted to {len(active_connections)} clients")
        
        # Send confirmation to sender
        emit('message_sent', {
            'status': 'success',
            'message_id': message_id,
            'message': f"Message sent with {'spoofed' if is_spoofed else 'real'} IP",
            'displayed_ip': displayed_ip,
            'is_spoofed': bool(is_spoofed),
            'timestamp': timestamp
        })
        
    except Exception as e:
        print(f"❌ Error sending message: {str(e)}")
        emit('error', {'message': f'Server error: {str(e)}'})

@socketio.on('analyze_message')
def handle_analyze_message(data):
    """Handle message analysis by defender"""
    try:
        message_id = data.get('message_id')
        guess = data.get('guess')  # 'spoofed' or 'legitimate'
        confidence = int(data.get('confidence', 50))
        
        if guess not in ['spoofed', 'legitimate']:
            emit('error', {'message': 'Invalid guess. Use "spoofed" or "legitimate"'})
            return
        
        if confidence < 0 or confidence > 100:
            emit('error', {'message': 'Confidence must be between 0 and 100'})
            return
        
        conn = sqlite3.connect('messages.db', check_same_thread=False)
        c = conn.cursor()
        
        # Get the message
        c.execute('SELECT is_spoofed, displayed_ip, real_ip, message FROM messages WHERE id = ?', 
                  (message_id,))
        msg = c.fetchone()
        
        if not msg:
            emit('error', {'message': 'Message not found'})
            return
        
        is_spoofed = bool(msg[0])
        displayed_ip = msg[1]
        real_ip = msg[2]
        message_text = msg[3]
        
        # Check if guess is correct
        is_correct = (
            (guess == 'spoofed' and is_spoofed) or
            (guess == 'legitimate' and not is_spoofed)
        )
        
        # Update message with analysis
        c.execute('''UPDATE messages 
                     SET detection_guess = ?, 
                         detection_correct = ?,
                         confidence = ?
                     WHERE id = ?''',
                  (guess, 1 if is_correct else 0, confidence, message_id))
        conn.commit()
        
        # Get user stats
        c.execute('''SELECT 
                        COUNT(*) as total_analyzed,
                        SUM(CASE WHEN detection_correct = 1 THEN 1 ELSE 0 END) as correct
                     FROM messages 
                     WHERE detection_guess IS NOT NULL''')
        user_stats = c.fetchone()
        
        conn.close()
        
        # Generate educational hints
        hints = generate_analysis_hints(real_ip, displayed_ip, is_spoofed, is_correct, message_text)
        
        # Prepare analysis result
        result = {
            'message_id': message_id,
            'your_guess': guess,
            'actual_status': 'spoofed' if is_spoofed else 'legitimate',
            'is_correct': is_correct,
            'confidence': confidence,
            'real_ip': real_ip,
            'displayed_ip': displayed_ip,
            'message': message_text,
            'hints': hints,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'user_stats': {
                'total_analyzed': user_stats[0] or 0,
                'correct': user_stats[1] or 0,
                'incorrect': (user_stats[0] or 0) - (user_stats[1] or 0),
                'accuracy': round((user_stats[1] or 0) / (user_stats[0] or 1) * 100, 1)
            }
        }
        
        # Send result to analyzer
        emit('analysis_result', result)
        
        # Broadcast updated message to all
        socketio.emit('message_analyzed', {
            'message_id': message_id,
            'detection_guess': guess,
            'detection_correct': is_correct,
            'analyzed_by': active_connections.get(request.sid, {}).get('role', 'defender')
        }, broadcast=True)
        
        print(f"🔍 Analysis: Guess={guess}, Correct={is_correct}, IP={displayed_ip}")
        
    except Exception as e:
        print(f"❌ Error analyzing message: {str(e)}")
        emit('error', {'message': f'Analysis error: {str(e)}'})

def generate_analysis_hints(real_ip, displayed_ip, is_spoofed, is_correct, message):
    """Generate educational hints for analysis"""
    hints = []
    
    if is_spoofed:
        hints.append("🎭 **SPOOFED IP DETECTED**")
        hints.append(f"📡 **Real sender**: {real_ip}")
        hints.append(f"🎭 **Displayed as**: {displayed_ip}")
        
        # Technical analysis
        if is_internal_ip(displayed_ip):
            hints.append("🔍 **Private IP range used** - Common in spoofing attacks")
            
            if displayed_ip.startswith("192.168."):
                hints.append("   • Class C private network (192.168.x.x)")
            elif displayed_ip.startswith("10."):
                hints.append("   • Class A private network (10.x.x.x)")
            elif displayed_ip.startswith("172.16."):
                hints.append("   • Class B private network (172.16.x.x - 172.31.x.x)")
            
            hints.append("   ⚠️ External traffic shouldn't come from private IPs")
        
        # Message content analysis
        suspicious_keywords = ['urgent', 'password', 'click', 'verify', 'reset', 'security', 'login']
        if any(keyword in message.lower() for keyword in suspicious_keywords):
            hints.append("📝 **Suspicious keywords detected** - Possible phishing attempt")
        
        # IP range consistency
        if real_ip.split('.')[:2] == displayed_ip.split('.')[:2]:
            hints.append("🎯 **Same subnet spoofing** - More sophisticated attack")
        else:
            hints.append("🌐 **Different subnet** - Classic IP spoofing")
            
    else:
        hints.append("✅ **LEGITIMATE COMMUNICATION**")
        hints.append(f"📡 **IP verified**: {real_ip}")
        
        if is_internal_ip(real_ip):
            hints.append("🏠 **Internal network traffic** - Expected behavior")
        else:
            hints.append("🌍 **External IP** - Normal internet traffic")
    
    # Educational tips
    hints.append("\n🔒 **DEFENSE TIPS:**")
    hints.append("1. **Ingress filtering** - Block packets with impossible source IPs")
    hints.append("2. **Egress filtering** - Prevent your network from sending spoofed packets")
    hints.append("3. **Use encryption** - SSL/TLS can prevent some MITM attacks")
    hints.append("4. **Implement IPsec** - For authenticated IP communications")
    
    if is_correct:
        hints.append("\n🎉 **GREAT JOB!** Your detection was correct!")
    else:
        hints.append("\n💡 **LEARNING OPPORTUNITY:**")
        if is_spoofed:
            hints.append("   Look for private IPs in external traffic")
        else:
            hints.append("   Not all suspicious-looking messages are spoofed")
    
    return hints

@socketio.on('request_history')
def handle_request_history():
    """Send message history to new client"""
    emit('message_history', {
        'messages': message_history[-50:],  # Last 50 messages
        'total': len(message_history),
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })

@socketio.on('simulate_attack')
def handle_simulate_attack(data):
    """Simulate various spoofing attacks"""
    attack_type = data.get('type', 'ddos')
    session_id = request.sid
    
    if session_id not in active_connections:
        emit('error', {'message': 'Not connected'})
        return
    
    attacks = {
        'ddos': {
            'name': 'DDoS Attack',
            'description': 'Distributed Denial of Service using spoofed IPs',
            'messages': [
                "🚀 Initiating SYN flood attack from multiple spoofed sources...",
                "📡 Amplifying UDP traffic towards target server 10.0.0.1...",
                "⚡ HTTP GET flood in progress - overwhelming web server...",
                "💣 ICMP ping flood detected from various IP ranges...",
                "🐌 Slowloris attack maintaining multiple connections..."
            ],
            'ips': [f"172.31.{random.randint(1,255)}.{random.randint(1,254)}" for _ in range(5)]
        },
        'phishing': {
            'name': 'Phishing Campaign',
            'description': 'Deceptive messages with spoofed sender addresses',
            'messages': [
                "📧 URGENT: Your account security has been compromised!",
                "🔐 Click http://verify-account.com to reset password immediately",
                "⚠️ Security Alert: Unusual login detected from new device",
                "🎯 Verify your identity: http://secure-login-update.com",
                "📱 Your subscription is about to expire - renew now!"
            ],
            'ips': ["192.168.1.100", "10.0.0.50", "172.16.0.25", "192.168.0.101"]
        },
        'mitm': {
            'name': 'Man-in-the-Middle',
            'description': 'Intercepting and modifying communications',
            'messages': [
                "🎯 Intercepted SSL handshake between client and server",
                "🔓 Session hijack successful - impersonating user 192.168.1.50",
                "🔄 Redirecting all traffic through proxy server 10.0.0.254",
                "📝 Capturing login credentials from unencrypted connections",
                "✏️ Modifying transaction data in real-time..."
            ],
            'ips': ["172.31.209.1", "172.31.209.254", "10.0.0.253"]
        },
        'scanning': {
            'name': 'Network Scanning',
            'description': 'Port scanning with spoofed source IPs',
            'messages': [
                "🔍 Scanning network 192.168.1.0/24 for open ports...",
                "📡 Port 22 (SSH) detected on 192.168.1.10",
                "🌐 Port 80 (HTTP) open on multiple hosts",
                "🔐 Port 443 (HTTPS) responding from web server",
                "🎯 Identifying service versions for vulnerability assessment"
            ],
            'ips': [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(3)]
        }
    }
    
    if attack_type not in attacks:
        emit('error', {'message': f'Invalid attack type. Choose from: {", ".join(attacks.keys())}'})
        return
    
    attack = attacks[attack_type]
    
    # Send multiple simulated messages
    for i, msg in enumerate(attack['messages'][:4]):  # Limit to 4 messages
        spoofed_ip = attack['ips'][i % len(attack['ips'])]
        
        # Prepare message data
        message_data = {
            'message': msg,
            'spoofed_ip': spoofed_ip,
            'use_spoofing': True,
            'attack_type': attack_type
        }
        
        # Use existing message handler
        handle_send_message(message_data)
        
        # Small delay between messages
        time.sleep(0.8)
    
    # Log the simulation
    attack_log = {
        'type': f'simulation_{attack_type}',
        'name': attack['name'],
        'description': attack['description'],
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'messages_sent': len(attack['messages'][:4])
    }
    attack_logs.append(attack_log)
    
    emit('attack_simulated', {
        'attack': attack_type,
        'name': attack['name'],
        'description': attack['description'],
        'count': 4,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })

@socketio.on('ping')
def handle_ping():
    """Handle ping/pong for connection monitoring"""
    if request.sid in active_connections:
        active_connections[request.sid]['last_activity'] = time.time()
    emit('pong', {'timestamp': time.time()})

def get_local_ip():
    """Get local IP address for network access"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return '127.0.0.1'

if __name__ == '__main__':
    # Clear terminal
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Get local IP
    local_ip = get_local_ip()
    
    # Print banner
    print("\n" + "═" * 70)
    print("        🎭 REAL-TIME IP SPOOFING LAB - ACADEMIC DEMONSTRATION")
    print("═" * 70)
    
    print("\n🎯 LEARNING OBJECTIVES:")
    print("   • Understand IP spoofing techniques and their impact")
    print("   • Practice detecting spoofed IP addresses")
    print("   • Learn defense mechanisms against spoofing attacks")
    
    print("\n👥 RECOMMENDED SETUP:")
    print("   • PC/Laptop: Hacker role (send spoofed messages)")
    print("   • Phone/Tablet: Defender role (detect spoofing)")
    print("   • Both devices on the SAME WiFi network")
    
    print(f"\n🌐 ACCESS URLs:")
    print(f"   • This computer: http://localhost:5000")
    print(f"   • Mobile devices: http://{local_ip}:5000")
    print(f"   • Network devices: http://{local_ip}:5000")
    
    print("\n⚡ FEATURES:")
    print("   • Real-time WebSocket communication")
    print("   • Mobile-responsive design")
    print("   • Multiple attack simulations (DDoS, Phishing, MITM, Scanning)")
    print("   • Educational hints and defense tips")
    print("   • Live statistics and connection monitoring")
    
    print("\n⚠️  SECURITY NOTICE:")
    print("   • This is an EDUCATIONAL TOOL only")
    print("   • All communication stays within your local network")
    print("   • No real IP spoofing occurs - simulation only")
    
    print("═" * 70)
    print("\n🚀 Starting server... (Press Ctrl+C to stop)")
    print("📊 Dashboard available at http://localhost:5000")
    print("📱 Mobile access at http://{}:5000".format(local_ip))
    
    # Start the server
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True,
        log_output=False
    )
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import sqlite3
from datetime import datetime
import random
import hashlib
import json
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ip-spoofing-lab-secret-2025'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)

# Store active connections
active_connections = {}
message_history = []

# Initialize database
def init_db():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  session_id TEXT,
                  role TEXT,
                  real_ip TEXT,
                  spoofed_ip TEXT,
                  displayed_ip TEXT,
                  is_spoofed INTEGER DEFAULT 0,
                  message TEXT,
                  timestamp DATETIME,
                  detection_guess TEXT,
                  detection_correct INTEGER,
                  confidence INTEGER)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    # Generate unique session ID
    if 'session_id' not in session:
        session['session_id'] = hashlib.md5(f"{datetime.now()}{random.random()}".encode()).hexdigest()[:10]
    
    # Default role based on device
    user_agent = request.headers.get('User-Agent', '').lower()
    if 'mobile' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
        default_role = 'defender'
        device = 'mobile'
    else:
        default_role = 'hacker'
        device = 'desktop'
    
    if 'role' not in session:
        session['role'] = default_role
    
    return render_template('index.html', 
                         session_id=session['session_id'],
                         role=session['role'],
                         device=device)

@app.route('/switch_role/<role>')
def switch_role(role):
    if role in ['hacker', 'defender']:
        session['role'] = role
        return jsonify({'status': 'success', 'role': role})
    return jsonify({'status': 'error', 'message': 'Invalid role'})

@app.route('/client_info')
def client_info():
    real_ip = request.remote_addr
    
    # Generate realistic spoofed IP examples
    spoof_examples = [
        {"ip": "192.168.1.100", "desc": "Common internal device"},
        {"ip": "10.0.0.50", "desc": "Network server"},
        {"ip": "172.16.0.25", "desc": "Another subnet"},
        {"ip": "8.8.8.8", "desc": "Google DNS"},
        {"ip": "1.1.1.1", "desc": "Cloudflare DNS"},
        {"ip": f"172.31.{random.randint(0,255)}.{random.randint(1,254)}", "desc": "Random internal"}
    ]
    
    return jsonify({
        'real_ip': real_ip,
        'spoof_examples': spoof_examples,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })

@app.route('/stats')
def get_stats():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    
    c.execute('''SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN is_spoofed = 1 THEN 1 ELSE 0 END) as spoofed,
                    SUM(CASE WHEN detection_correct = 1 THEN 1 ELSE 0 END) as correct_detections
                 FROM messages''')
    stats = c.fetchone()
    
    c.execute('''SELECT role, COUNT(*) as count 
                 FROM messages 
                 GROUP BY role''')
    role_stats = c.fetchall()
    
    c.execute('''SELECT displayed_ip, COUNT(*) as count 
                 FROM messages 
                 WHERE is_spoofed = 1 
                 GROUP BY displayed_ip 
                 ORDER BY count DESC 
                 LIMIT 5''')
    top_spoofed = c.fetchall()
    
    conn.close()
    
    return jsonify({
        'total_messages': stats[0] or 0,
        'spoofed_messages': stats[1] or 0,
        'legitimate_messages': (stats[0] or 0) - (stats[1] or 0),
        'correct_detections': stats[2] or 0,
        'role_distribution': {role: count for role, count in role_stats},
        'top_spoofed_ips': [{"ip": ip, "count": count} for ip, count in top_spoofed],
        'spoofing_rate': round((stats[1] or 0) / (stats[0] or 1) * 100, 1)
    })

@socketio.on('connect')
def handle_connect():
    session_id = request.sid
    active_connections[session_id] = {
        'connected_at': time.time(),
        'role': session.get('role', 'hacker')
    }
    
    print(f"🔗 New connection: {session_id} as {active_connections[session_id]['role']}")
    emit('connection_established', {
        'session_id': session_id,
        'role': active_connections[session_id]['role'],
        'message': 'Connected to IP Spoofing Lab'
    })

@socketio.on('disconnect')
def handle_disconnect():
    session_id = request.sid
    if session_id in active_connections:
        role = active_connections[session_id]['role']
        del active_connections[session_id]
        print(f"🔌 Disconnected: {session_id} ({role})")

@socketio.on('send_message')
def handle_send_message(data):
    try:
        session_id = request.sid
        message = data.get('message', '').strip()
        spoofed_ip = data.get('spoofed_ip', '').strip()
        use_spoofing = data.get('use_spoofing', False)
        
        if not message:
            emit('error', {'message': 'Message cannot be empty'})
            return
        
        real_ip = request.remote_addr
        
        # Determine displayed IP
        if use_spoofing and spoofed_ip:
            displayed_ip = spoofed_ip
            is_spoofed = 1
            attack_type = 'ip_spoofing'
        else:
            displayed_ip = real_ip
            is_spoofed = 0
            attack_type = 'legitimate'
            spoofed_ip = real_ip
        
        # Get role from session
        role = session.get('role', 'hacker')
        
        # Store in database
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        c.execute('''INSERT INTO messages 
                     (session_id, role, real_ip, spoofed_ip, displayed_ip, 
                      is_spoofed, message, timestamp) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (session_id, role, real_ip, spoofed_ip, displayed_ip,
                   is_spoofed, message, timestamp))
        
        message_id = c.lastrowid
        conn.commit()
        
        # Get the message for broadcasting
        c.execute('SELECT * FROM messages WHERE id = ?', (message_id,))
        msg = c.fetchone()
        conn.close()
        
        # Create message object
        message_obj = {
            'id': msg[0],
            'session_id': msg[1],
            'role': msg[2],
            'real_ip': msg[3],
            'spoofed_ip': msg[4],
            'displayed_ip': msg[5],
            'is_spoofed': bool(msg[6]),
            'message': msg[7],
            'timestamp': msg[8],
            'attack_type': attack_type
        }
        
        # Add to history (keep last 50)
        message_history.append(message_obj)
        if len(message_history) > 50:
            message_history.pop(0)
        
        # Log the action
        action = "🎭 SPOOFED" if is_spoofed else "✅ LEGITIMATE"
        print(f"\n{action} MESSAGE")
        print(f"   Role: {role}")
        print(f"   Real IP: {real_ip}")
        print(f"   Displayed IP: {displayed_ip}")
        print(f"   Message: {message[:50]}...")
        
        # Broadcast to all connected clients
        socketio.emit('new_message', message_obj)
        
        # Send confirmation to sender
        emit('message_sent', {
            'status': 'success',
            'message': f"Message sent with {'spoofed' if is_spoofed else 'real'} IP",
            'displayed_ip': displayed_ip
        })
        
    except Exception as e:
        print(f"❌ Error sending message: {e}")
        emit('error', {'message': f'Error: {str(e)}'})

@socketio.on('analyze_message')
def handle_analyze_message(data):
    try:
        message_id = data.get('message_id')
        guess = data.get('guess')  # 'spoofed' or 'legitimate'
        confidence = data.get('confidence', 50)
        
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        
        # Get the message
        c.execute('SELECT is_spoofed, displayed_ip, real_ip FROM messages WHERE id = ?', (message_id,))
        msg = c.fetchone()
        
        if not msg:
            emit('error', {'message': 'Message not found'})
            return
        
        is_spoofed = bool(msg[0])
        displayed_ip = msg[1]
        real_ip = msg[2]
        
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
        hints = generate_analysis_hints(real_ip, displayed_ip, is_spoofed, is_correct)
        
        # Prepare analysis result
        result = {
            'message_id': message_id,
            'your_guess': guess,
            'actual_status': 'spoofed' if is_spoofed else 'legitimate',
            'is_correct': is_correct,
            'confidence': confidence,
            'real_ip': real_ip,
            'displayed_ip': displayed_ip,
            'hints': hints,
            'user_stats': {
                'total_analyzed': user_stats[0] or 0,
                'correct': user_stats[1] or 0,
                'accuracy': round((user_stats[1] or 0) / (user_stats[0] or 1) * 100, 1)
            }
        }
        
        # Send result to analyzer
        emit('analysis_result', result)
        
        # Broadcast updated message to all
        socketio.emit('message_updated', {
            'message_id': message_id,
            'detection_guess': guess,
            'detection_correct': is_correct
        })
        
        print(f"🔍 Analysis: Guess={guess}, Correct={is_correct}, IP={displayed_ip}")
        
    except Exception as e:
        print(f"❌ Error analyzing message: {e}")
        emit('error', {'message': f'Analysis error: {str(e)}'})

def generate_analysis_hints(real_ip, displayed_ip, is_spoofed, is_correct):
    """Generate educational hints for analysis"""
    hints = []
    
    if is_spoofed:
        hints.append("🎭 This was a SPOOFED IP attack")
        hints.append(f"📡 Real sender: {real_ip}")
        hints.append(f"🎭 Displayed as: {displayed_ip}")
        
        # Technical analysis
        if displayed_ip.startswith("192.168."):
            hints.append("🔍 Private IP range used (common in spoofing)")
        if displayed_ip.startswith("10."):
            hints.append("🔍 Class A private IP detected")
        if displayed_ip.startswith("172.16."):
            hints.append("🔍 Class B private IP detected")
        if real_ip.split('.')[:2] == displayed_ip.split('.')[:2]:
            hints.append("🎯 Same subnet spoofing - harder to detect")
            
    else:
        hints.append("✅ This was LEGITIMATE communication")
        hints.append(f"📡 IP addresses match: {real_ip}")
        
    if is_correct:
        hints.append("🎉 Your detection was CORRECT!")
    else:
        hints.append("💡 Remember: Check for private IPs in external traffic")
        
    hints.append("🔒 Tip: Use ingress filtering to prevent spoofing")
    
    return hints

@socketio.on('request_history')
def handle_request_history():
    """Send message history to new client"""
    emit('message_history', {
        'messages': message_history[-20:],  # Last 20 messages
        'total': len(message_history)
    })

@socketio.on('simulate_attack')
def handle_simulate_attack(data):
    """Simulate various spoofing attacks"""
    attack_type = data.get('type', 'ddos')
    session_id = request.sid
    real_ip = request.remote_addr
    
    attacks = {
        'ddos': {
            'name': 'DDoS Attack Simulation',
            'messages': [
                "SYN flood initiated from multiple sources",
                "UDP amplification attack in progress",
                "HTTP GET flood from botnet",
                "ICMP ping flood detected",
                "Slowloris attack targeting web server"
            ],
            'ips': [f"172.31.{random.randint(1,255)}.{random.randint(1,254)}" for _ in range(5)]
        },
        'phishing': {
            'name': 'Phishing Campaign',
            'messages': [
                "URGENT: Your account has been compromised",
                "Click here to reset your password",
                "Security alert: Unusual login detected",
                "Verify your identity immediately",
                "Your subscription is about to expire"
            ],
            'ips': ["192.168.1.100", "10.0.0.50", "172.16.0.25"]
        },
        'mitm': {
            'name': 'Man-in-the-Middle',
            'messages': [
                "Intercepted SSL handshake",
                "Session hijack successful",
                "Redirecting traffic through proxy",
                "Capturing login credentials",
                "Modifying transaction data"
            ],
            'ips': ["172.31.209.1", "172.31.209.254"]
        }
    }
    
    if attack_type not in attacks:
        emit('error', {'message': 'Invalid attack type'})
        return
    
    attack = attacks[attack_type]
    
    # Send multiple simulated messages
    for i, msg in enumerate(attack['messages'][:3]):  # Limit to 3 messages
        spoofed_ip = attack['ips'][i % len(attack['ips'])]
        
        message_obj = {
            'id': f"sim_{time.time()}_{i}",
            'session_id': 'simulation',
            'role': 'hacker',
            'real_ip': real_ip,
            'spoofed_ip': spoofed_ip,
            'displayed_ip': spoofed_ip,
            'is_spoofed': True,
            'message': msg,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'attack_type': attack_type,
            'is_simulation': True
        }
        
        # Add to history
        message_history.append(message_obj)
        
        # Broadcast
        socketio.emit('new_message', message_obj)
        
        time.sleep(0.5)  # Small delay between messages
    
    emit('attack_simulated', {
        'attack': attack_type,
        'name': attack['name'],
        'count': 3
    })

@app.route('/clear_all', methods=['POST'])
def clear_all():
    """Clear all messages"""
    try:
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute('DELETE FROM messages')
        conn.commit()
        conn.close()
        
        # Clear message history
        message_history.clear()
        
        # Notify all clients
        socketio.emit('all_cleared', {'message': 'All messages cleared'})
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("\n" + "═" * 60)
    print("        🎭 REAL-TIME IP SPOOFING LAB")
    print("═" * 60)
    print("\n🎯 ACADEMIC DEMONSTRATION:")
    print("   • Hacker Interface: Spoof IP addresses")
    print("   • Defender Interface: Detect spoofing attempts")
    print("   • Real-time messaging between devices")
    print("\n📱 PLATFORMS:")
    print("   • PC: Hacker mode (default)")
    print("   • Mobile: Defender mode (default)")
    print("\n🌐 ACCESS:")
    print("   • PC: http://localhost:5000")
    print("   • Phone: http://YOUR_PC_IP:5000")
    print("\n⚡ FEATURES:")
    print("   • Real-time WebSocket communication")
    print("   • Responsive design for all devices")
    print("   • Attack simulation (DDoS, Phishing, MITM)")
    print("   • Educational detection hints")
    print("   • Live statistics and analytics")
    print("═" * 60)
    print("\n🚀 Starting server...")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
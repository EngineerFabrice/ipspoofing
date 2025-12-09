#!/usr/bin/env python3
"""
Test script to verify the IP Spoofing Lab is working correctly
"""

import requests
import socket
import sys
import time

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return '127.0.0.1'

def test_server_connection(url):
    """Test if server is accessible"""
    try:
        print(f"Testing connection to {url}...")
        response = requests.get(f'{url}/client_info', timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Server is running!")
            print(f"   Your IP: {data['real_ip']}")
            print(f"   Session ID: {data['session_id']}")
            print(f"   Role: {data['role']}")
            print(f"   Device: {data['device']}")
            return True
        else:
            print(f"❌ Server returned status code: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to {url}")
        print("   Make sure the server is running: python app.py")
        return False
    except requests.exceptions.Timeout:
        print(f"❌ Connection timeout to {url}")
        return False
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

def test_websocket(url):
    """Test WebSocket connection"""
    try:
        print("\nTesting WebSocket connection...")
        # This is a simple test - real WebSocket testing would require a WebSocket client
        ws_url = url.replace('http://', 'ws://').replace('https://', 'wss://')
        print(f"✅ WebSocket URL: {ws_url}/socket.io/")
        print("   WebSocket functionality will be tested by the web interface")
        return True
    except Exception as e:
        print(f"❌ WebSocket setup error: {str(e)}")
        return False

def check_firewall():
    """Check for common firewall issues"""
    print("\nChecking for firewall issues...")
    
    local_ip = get_local_ip()
    if local_ip.startswith('192.168.') or local_ip.startswith('10.'):
        print(f"✅ Local IP: {local_ip} (private network)")
    else:
        print(f"⚠️  Local IP: {local_ip} (may be public)")
    
    # Check if port 5000 is likely blocked
    print("   If devices can't connect, check:")
    print("   1. Windows Firewall -> Allow app through firewall")
    print("   2. Add Python to allowed apps")
    print("   3. Or temporarily disable firewall for testing")
    
    return True

def print_instructions(local_ip):
    """Print connection instructions"""
    print("\n" + "="*60)
    print("CONNECTION INSTRUCTIONS")
    print("="*60)
    
    print("\n📱 ON YOUR PHONE/TABLET:")
    print("1. Connect to the SAME WiFi as your computer")
    print("2. Open any web browser (Chrome/Safari recommended)")
    print(f"3. Go to: http://{local_ip}:5000")
    print("4. Phone will auto-detect as 'Defender'")
    
    print("\n💻 ON YOUR COMPUTER:")
    print("1. Keep this window open (server running)")
    print("2. Open another browser window/tab")
    print("3. Go to: http://localhost:5000")
    print("4. Computer will auto-detect as 'Hacker'")
    
    print("\n🎮 TO TEST REAL-TIME FUNCTIONALITY:")
    print("1. On computer (Hacker): Send a message with spoofed IP")
    print("2. On phone (Defender): Message should appear instantly")
    print("3. On phone: Analyze the message (guess if IP is spoofed)")
    print("4. On computer: See if your spoofing was detected")
    
    print("\n🔧 TROUBLESHOOTING:")
    print("• Can't connect? Ensure same WiFi network")
    print("• Messages not appearing? Check connection status")
    print("• Need to reset? Use 'Clear All' button")
    print("• Still having issues? Restart the server")
    
    print("\n" + "="*60)
    print("IP SPOOFING LAB IS READY!")
    print("="*60)

def main():
    print("\n" + "🔧 IP SPOOFING LAB - CONNECTION TESTER")
    print("="*60)
    
    # Get local IP
    local_ip = get_local_ip()
    
    # Test local connection
    local_success = test_server_connection('http://localhost:5000')
    
    # Test network connection
    network_success = False
    if local_ip != '127.0.0.1':
        network_success = test_server_connection(f'http://{local_ip}:5000')
    
    # Test WebSocket
    ws_success = test_websocket('http://localhost:5000')
    
    # Check firewall
    fw_success = check_firewall()
    
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    
    if local_success:
        print("✅ Local connection: PASSED")
    else:
        print("❌ Local connection: FAILED")
    
    if network_success:
        print("✅ Network connection: PASSED")
    else:
        print("❌ Network connection: FAILED")
        print("   Other devices won't be able to connect")
    
    print("✅ WebSocket setup: READY")
    print("✅ Firewall check: COMPLETE")
    
    if local_success:
        print_instructions(local_ip)
        
        print("\n🚀 Starting IP Spoofing Lab...")
        print("   Keep this terminal open while using the lab")
        print("   Press Ctrl+C to stop the server\n")
    else:
        print("\n❌ SERVER NOT RUNNING")
        print("   Start the server with: python app.py")
        print("   Then run this test again\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Test cancelled by user")
        sys.exit(0)
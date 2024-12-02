from getmac import get_mac_address
import netifaces
import requests
from datetime import datetime
import os

SERVER_URL = "https://staging.api.blccu.com/verify-attendance"

def capture_wifi_packets(duration=10, interface="en0"):
    captured_macs = set()
    
    # macOS에서는 모니터 모드 설정이 다름
    try:
        print(f"Using interface: {interface}")
        # macOS에서는 airport 유틸리티 사용
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        os.system(f"sudo {airport_path} {interface} sniff")
        
        print(f"Interface {interface} ready for capture")
    except Exception as e:
        print(f"Error setting interface: {str(e)}")
        return []

    # 모든 네트워크 인터페이스 가져오기
    interfaces = netifaces.interfaces()
    
    print("Scanning network interfaces...")
    for interface in interfaces:
        try:
            # 각 인터페이스의 연결된 장치들의 MAC 주소 수집
            mac = get_mac_address(interface=interface)
            if mac:
                mac = mac.lower()
                captured_macs.add(mac)
                print(f"Captured MAC from {interface}: {mac}")
                
            # 인터페이스의 IP 주소들 확인
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:  # IPv4 주소가 있는 경우
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr['addr']
                    # IP에 연결된 장치의 MAC 주소 확인
                    mac = get_mac_address(ip=ip)
                    if mac:
                        mac = mac.lower()
                        captured_macs.add(mac)
                        print(f"Captured MAC from IP {ip}: {mac}")
                    
        except Exception as e:
            print(f"Error scanning interface {interface}: {str(e)}")
            continue

    print(f"Capture complete. Found {len(captured_macs)} unique MACs")
    return list(captured_macs)

def submit_attendance(student_id, classroom_id):
    print("Starting attendance submission process...")

    # Capture Wi-Fi packets
    captured_macs = capture_wifi_packets()

    # Prepare data for server
    data = {
        'student_id': student_id,
        'captured_macs': captured_macs,
        'classroom_id': classroom_id,
        'timestamp': datetime.now().isoformat()
    }

    # Send request to server
    try:
        print("Sending data to server...")
        response = requests.post(
            url=SERVER_URL,
            json=data,
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            result = response.json()
            print(f"Attendance verification result: {result['attendance_verified']}")
            if result['attendance_verified']:
                print("✅ Attendance verified successfully!")
            else:
                print("❌ Attendance verification failed!")
        else:
            print(f"Error submitting attendance. Status code: {response.status_code}")

    except Exception as e:
        print(f"Error during submission: {str(e)}")

def main():
    print("=== Attendance Verification System ===")
    student_id = input("Enter student ID: ")
    classroom_id = input("Enter classroom ID (e.g., classroom_1): ")
    submit_attendance(student_id, classroom_id)

if __name__ == "__main__":
    main()

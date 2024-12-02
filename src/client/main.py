from getmac import get_mac_address
import netifaces
import requests
from datetime import datetime
import os

SERVER_URL = 'https://staging.api.blccu.com'

def capture_wifi_packets(duration=10, interface="en0"):
    captured_macs = set()

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
    print(f"Captured MACs: {captured_macs}")

    # Prepare data for server
    data = {
        'student_id': student_id,
        'captured_macs': captured_macs,
        'classroom_id': classroom_id,
    }

    # Send request to server
    try:
        print("Sending data to server...")
        response = requests.post(
            url=SERVER_URL + "/verify-attendance",
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

def check_attendance_list():
    URL = SERVER_URL + "/attendance"

    try:
        response = requests.get(url=URL, headers={'Content-Type': 'application/json'})
        result = response.json()
        print("Printing attendance list:")
        for attendance in result:
            print(f"Student ID: {attendance['student_id']:<15} "
                  f"Timestamp: {attendance['timestamp']}")
    except Exception as e:
        print(f"Error during attendance list check: {str(e)}")


def main():
    print("=== Attendance Verification System ===")
    print("Enter the wanted process:")
    print("1. Verify attendance")
    print("2. Check attendance list")
    process = input(": ")

    if process == "1":
        student_id = input("Enter student ID: ")
        response = requests.get(url=SERVER_URL + "/valid-macs", headers={'Content-Type': 'application/json'})
        result = response.json()
        # 교실 목록을 번호와 함께 예쁘게 출력
        print("\nClassrooms:")
        for idx, classroom in enumerate(result.keys(), 1):
            print(f"- {classroom}")
        print()  # 빈 줄 추가로 가독성 향상
        classroom_id = input("Enter classroom ID (e.g., classroom_1): ")
        submit_attendance(student_id, classroom_id)
    elif process == "2":
        check_attendance_list();

if __name__ == "__main__":
    main()




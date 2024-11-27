from scapy.all import sniff
from scapy.layers.dot11 import Dot11
import requests
from datetime import datetime

def capture_wifi_packets(duration=10):
    captured_macs = set()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            # Extract MAC addresses from Wi-Fi packets
            mac = None

            # Try to get MAC from different fields
            if pkt.addr2:  # Source MAC
                mac = pkt.addr2
            elif pkt.addr1:  # Destination MAC
                mac = pkt.addr1
            elif pkt.addr3:  # BSSID
                mac = pkt.addr3

            if mac:
                # Convert MAC to a standardized format
                mac = mac.lower()
                captured_macs.add(mac)
                print(f"Captured MAC: {mac}")  # Debug print

    print("Starting packet capture...")
    try:
        sniff(prn=packet_handler, timeout=duration)
    except Exception as e:
        print(f"Error during packet capture: {str(e)}")

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

    # Server URL
    SERVER_URL = 'http://localhost:5000/verify-attendance'

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

from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# Simulated database of valid AP MAC addresses
VALID_AP_MACS = {
    # Example MAC addresses (to be replaced)
    "classroom_1": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"],
}

@app.route('/verify-attendance', methods=['POST'])
def verify_attendance():
    try:
        data = request.get_json()
        student_id = data.get('student_id')
        captured_macs = data.get('captured_macs', [])
        classroom_id = data.get('classroom_id')

        # Verify if any captured MAC matches valid MACs for the classroom
        valid_macs = VALID_AP_MACS.get(classroom_id, [])
        is_present = any(mac in valid_macs for mac in captured_macs)

        response = {
            'student_id': student_id,
            'attendance_verified': is_present,
            'timestamp': datetime.now().isoformat()
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

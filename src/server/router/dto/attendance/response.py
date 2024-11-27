from pydantic import BaseModel
class AttendanceResponse(BaseModel):
    student_id: str
    attendance_verified: bool
    timestamp: str

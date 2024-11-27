from pydantic import BaseModel
from typing import List


class AttendanceRequest(BaseModel):
    student_id: str
    captured_macs: List[str]
    classroom_id: str

from fastapi import APIRouter
from typing import List
from .dto.attendance.request import AttendanceRequest
from .dto.attendance.response import AttendanceResponse
from datetime import datetime
from fastapi import HTTPException
from ..constant.valid_ap_macs import VALID_AP_MACS
import aiosqlite
from ..constant.database import DATABASE

app_router = APIRouter()



@app_router.get("/attendance", response_model=List[AttendanceResponse])
async def get_attendance():
    async with aiosqlite.connect(DATABASE) as db:
        cursor = await db.execute("SELECT * FROM attendance")
        data = await cursor.fetchall()
        return [AttendanceResponse(
            student_id=row[0],
            attendance_verified=row[1],
            timestamp=row[2]
        ) for row in data]

@app_router.post("/verify-attendance", response_model=AttendanceResponse)
async def verify_attendance(request: AttendanceRequest):
    try:
        async with aiosqlite.connect(DATABASE) as db:
            valid_macs = VALID_AP_MACS.get(request.classroom_id, [])
            is_present = any(mac in valid_macs for mac in request.captured_macs)
            response = AttendanceResponse(
                student_id=request.student_id,
                attendance_verified=is_present,
                timestamp=datetime.now().isoformat()
            )
            await db.execute("""
                INSERT INTO attendance (student_id, attendance_verified, timestamp)
                VALUES (?, ?, ?)
            """, (request.student_id, is_present, datetime.now().isoformat()))
            await db.commit()
            return response

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    

@app_router.post("/clear-attendance")
async def clear_attendance():
    async with aiosqlite.connect(DATABASE) as db:
        await db.execute("DELETE FROM attendance")
        await db.commit()
    return {"message": "Attendance data cleared"}
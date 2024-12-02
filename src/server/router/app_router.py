from fastapi import APIRouter
from typing import List
from .dto.attendance.request import AttendanceRequest
from .dto.attendance.response import AttendanceResponse
from datetime import datetime
from fastapi import HTTPException
import aiosqlite
from ..constant.database import DATABASE
from pydantic import BaseModel

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
            # DB에서 유효한 MAC 주소 조회
            cursor = await db.execute("""
                SELECT mac_address FROM valid_ap_macs 
                WHERE classroom_id = ?
            """, (request.classroom_id,))
            valid_macs = [row[0] for row in await cursor.fetchall()]
            
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

# MAC 주소 등록을 위한 DTO
class RegisterMacRequest(BaseModel):
    classroom_id: str
    mac_address: str

@app_router.post("/register-mac")
async def register_mac(request: RegisterMacRequest):
    async with aiosqlite.connect(DATABASE) as db:
        await db.execute("""
            REPLACE INTO valid_ap_macs (classroom_id, mac_address)
            VALUES (?, ?)
        """, (request.classroom_id, request.mac_address))
        await db.commit()
    return {"message": f"MAC address registered for classroom {request.classroom_id}"}

@app_router.get("/valid-macs")
async def get_valid_macs():
    async with aiosqlite.connect(DATABASE) as db:
        cursor = await db.execute("""
            SELECT classroom_id, GROUP_CONCAT(mac_address) as mac_addresses 
            FROM valid_ap_macs 
            GROUP BY classroom_id
        """)
        rows = await cursor.fetchall()
        
        result = {}
        for row in rows:
            classroom_id, mac_addresses = row
            result[classroom_id] = mac_addresses.split(',') if mac_addresses else []
            
        return {"classrooms": result}

@app_router.post("/clear-mac-addresses")
async def clear_mac_addresses():
    async with aiosqlite.connect(DATABASE) as db:
        await db.execute("DELETE FROM valid_ap_macs")
        await db.commit()
    return {"message": "All MAC addresses cleared"}
        
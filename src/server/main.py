from fastapi import FastAPI
from .constant.database import DATABASE
from .router.app_router import app_router
import aiosqlite
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    await initialize_database()
    yield

async def initialize_database():
    async with aiosqlite.connect(DATABASE) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                student_id TEXT,
                attendance_verified BOOLEAN,
                timestamp TEXT,
                PRIMARY KEY (student_id, timestamp)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS valid_ap_macs (
                classroom_id TEXT,
                mac_address TEXT,
                PRIMARY KEY (classroom_id, mac_address)
            )
        """)
        await db.commit()


app = FastAPI(lifespan=lifespan)
app.include_router(app_router)

def run_server():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)

if __name__ == "__main__":
    run_server()



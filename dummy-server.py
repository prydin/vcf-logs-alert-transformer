from typing import Any
from fastapi import FastAPI, Body
import uvicorn

app = FastAPI()
@app.post("/ingest")
async def receive_event(event: Any = Body(...)):
    print("Received event:", event)
    return {"status": "received"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8888)
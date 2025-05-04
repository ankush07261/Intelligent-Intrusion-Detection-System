from fastapi import FastAPI
import threading
import os
import json
from extract import background_capture
from registration import router as register_router
from login import router as login_router
from convert import get_predictions
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(register_router)
app.include_router(login_router)

@app.on_event("startup")
def start_capture():
    thread = threading.Thread(target=background_capture, daemon=True)
    thread.start()

@app.get("/")
def read_root():
    return {"message": "FastAPI is working and capturing packets."}

@app.get("/packets")
def get_packets():
    JSON_FILE = "capture_data.json"
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    return []

@app.get("/predictions")
def get_predictions_route(page: int = 1, page_size: int = 500):
    predictions = get_predictions(page, page_size)
    if "error" in predictions:
        return {"error": predictions["error"]}
    return predictions

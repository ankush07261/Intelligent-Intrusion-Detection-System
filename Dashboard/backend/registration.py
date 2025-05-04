from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from passlib.hash import bcrypt
import mysql.connector

router = APIRouter()

class UserRegister(BaseModel):
    username: str
    password: str

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="hallo",
        database="project"
    )

@router.post("/register")
def register_user(user: UserRegister):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM users WHERE username = %s", (user.username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = bcrypt.hash(user.password)
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (user.username, hashed_pw))
    db.commit()

    cursor.close()
    db.close()
    return {"message": "User registered successfully"}
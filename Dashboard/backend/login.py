from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from passlib.hash import bcrypt
from jose import JWTError, jwt
import mysql.connector
import datetime

router = APIRouter()

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

class UserLogin(BaseModel):
    username: str
    password: str

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="<your_password>",
        database="project"
    )

@router.post("/login")
def login(user: UserLogin):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username = %s", (user.username,))
    result = cursor.fetchone()

    cursor.close()
    db.close()

    if not result or not bcrypt.verify(user.password, result["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    token = jwt.encode({"sub": user.username, "exp": expiration}, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": token, "token_type": "bearer"}

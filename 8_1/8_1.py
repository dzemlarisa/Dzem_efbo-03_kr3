from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from database import get_db_connection, create_tables

app = FastAPI()

create_tables()

class User(BaseModel):
    username: str
    password: str

@app.post("/register")
def register(user: User):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (user.username, user.password)
    )

    conn.commit()
    conn.close()

    return {"message": "User registered successfully!"}
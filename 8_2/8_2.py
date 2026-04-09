from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
from contextlib import contextmanager

app = FastAPI()

@contextmanager
def get_db():
    conn = sqlite3.connect("todos.db")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                completed BOOLEAN NOT NULL DEFAULT 0
            )
        """)
        conn.commit()

init_db()

class TodoCreate(BaseModel):
    title: str
    description: str

class TodoUpdate(BaseModel):
    title: str
    description: str
    completed: bool

class TodoResponse(BaseModel):
    id: int
    title: str
    description: str
    completed: bool

@app.post("/todos", response_model=TodoResponse, status_code=201)
def create_todo(todo: TodoCreate):
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO todos (title, description) VALUES (?, ?)",
            (todo.title, todo.description)
        )
        conn.commit()
        todo_id = cursor.lastrowid

        cursor = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()

        return TodoResponse(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            completed=bool(row["completed"])
        )

@app.get("/todos/{todo_id}", response_model=TodoResponse)
def get_todo(todo_id: int):
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Todo not found")

        return TodoResponse(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            completed=bool(row["completed"])
        )

@app.put("/todos/{todo_id}", response_model=TodoResponse)
def update_todo(todo_id: int, todo: TodoUpdate):
    with get_db() as conn:
        cursor = conn.execute(
            "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
            (todo.title, todo.description, todo.completed, todo_id)
        )
        conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Todo not found")

        cursor = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()

        return TodoResponse(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            completed=bool(row["completed"])
        )

@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int):
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Todo not found")

        return {"message": "Todo deleted successfully"}
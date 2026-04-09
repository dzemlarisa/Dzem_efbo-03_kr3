from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import os

from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"

ROLE_PERMISSIONS: Dict[Role, List[str]] = {
    Role.ADMIN: ["create", "read", "update", "delete"],
    Role.USER: ["read", "update"]
}

users_db = {}

class UserRegister(BaseModel):
    username: str
    password: str
    role: Role = Role.USER

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: Dict

class UserResponse(BaseModel):
    username: str
    role: Role
    message: str

class ResourceCreate(BaseModel):
    name: str

class ResourceUpdate(BaseModel):
    name: str

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_user(username: str):
    if username in users_db:
        return users_db[username]
    return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"username": username, "role": user["role"]}

def require_roles(allowed_roles: List[Role]):
    def role_checker(current_user=Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return role_checker

@app.post("/register", response_model=UserResponse)
def register(user_data: UserRegister):
    if user_data.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    hashed_password = get_password_hash(user_data.password)
    users_db[user_data.username] = {
        "role": user_data.role,
        "password": hashed_password
    }

    return UserResponse(
        username=user_data.username,
        role=user_data.role,
        message="User registered successfully"
    )

@app.post("/login", response_model=Token)
def login(user_data: UserLogin):
    user = get_user(user_data.username)

    if not user or not verify_password(user_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user_data.username, "role": user["role"].value}
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        user={"username": user_data.username, "role": user["role"].value}
    )

@app.get("/protected_resource")
def get_protected_resource(current_user=Depends(require_roles([Role.ADMIN, Role.USER]))):
    return {
        "message": "This is a protected resource",
        "user": current_user["username"],
        "role": current_user["role"]
    }

@app.post("/admin/resources")
def create_resource(
        resource: ResourceCreate,
        current_user=Depends(require_roles([Role.ADMIN]))
):
    new_id = len(resources) + 1
    new_resource = {"id": new_id, "name": resource.name, "owner": current_user["username"]}
    resources.append(new_resource)
    return {"message": "Resource created", "resource": new_resource}

@app.delete("/admin/resources/{resource_id}")
def delete_resource(
        resource_id: int,
        current_user=Depends(require_roles([Role.ADMIN]))
):
    for i, res in enumerate(resources):
        if res["id"] == resource_id:
            deleted = resources.pop(i)
            return {"message": "Resource deleted", "resource": deleted}
    raise HTTPException(status_code=404, detail="Resource not found")

@app.get("/user/resources")
def get_resources(current_user=Depends(require_roles([Role.USER, Role.ADMIN]))):
    return {"resources": resources}

@app.put("/user/resources/{resource_id}")
def update_resource(
        resource_id: int,
        resource_update: ResourceUpdate,
        current_user=Depends(require_roles([Role.USER, Role.ADMIN]))
):
    for res in resources:
        if res["id"] == resource_id:
            res["name"] = resource_update.name
            return {"message": "Resource updated", "resource": res}
    raise HTTPException(status_code=404, detail="Resource not found")

@app.get("/guest/resources")
def get_resources_readonly():
    return {"resources": [{"id": r["id"], "name": r["name"]} for r in resources]}

def init_test_users():
    if not users_db:
        users_db["admin_user"] = {
            "role": Role.ADMIN,
            "password": get_password_hash("admin")
        }
        users_db["regular_user"] = {
            "role": Role.USER,
            "password": get_password_hash("user")
        }

init_test_users()

resources = [
    {"id": 1, "name": "Resource 1", "owner": "user"},
    {"id": 2, "name": "Resource 2", "owner": "admin"}
]
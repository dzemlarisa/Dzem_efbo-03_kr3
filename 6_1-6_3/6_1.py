import os
import secrets
from typing import Dict, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from dotenv import load_dotenv
from enum import Enum

load_dotenv()

class Mode(str, Enum):
    DEV = "DEV"
    PROD = "PROD"

class Settings:
    def __init__(self):
        self.MODE = os.getenv("MODE", "DEV").upper()

        if self.MODE not in [Mode.DEV.value, Mode.PROD.value]:
            raise ValueError(f"Invalid MODE value: {self.MODE}. Must be DEV or PROD")

        self.DOCS_USER = os.getenv("DOCS_USER", "admin")
        self.DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "123")

settings = Settings()

security = HTTPBasic(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
fake_users_db: Dict[str, "UserInDB"] = {}

class UserBase(BaseModel):
    username: str
    password: str

class User(UserBase):
    """Модель для регистрации пользователя"""
    pass

class UserInDB(UserBase):
    """Модель для хранения в базе данных"""
    hashed_password: str

    class Config:
        fields = {
            'password': {'exclude': True}
        }

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str) -> Optional[UserInDB]:
    return fake_users_db.get(username)

def verify_docs_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Basic"},
        )

    is_username_correct = secrets.compare_digest(
        credentials.username, settings.DOCS_USER
    )
    is_password_correct = secrets.compare_digest(
        credentials.password, settings.DOCS_PASSWORD
    )

    if not (is_username_correct and is_password_correct):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return True

async def auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Basic"},
        )

    user = get_user(credentials.username)

    if user is None:
        secrets.compare_digest(credentials.username, credentials.username)
        secrets.compare_digest(credentials.password, "dummy")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    is_password_valid = verify_password(credentials.password, user.hashed_password)
    is_username_valid = secrets.compare_digest(credentials.username, user.username)

    if not (is_username_valid and is_password_valid):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return user

def create_app() -> FastAPI:
    if settings.MODE == Mode.PROD.value:
        app = FastAPI(
            title="Secure API",
            docs_url=None,
            redoc_url=None,
            openapi_url=None
        )

        @app.get("/docs", include_in_schema=False)
        @app.get("/redoc", include_in_schema=False)
        @app.get("/openapi.json", include_in_schema=False)
        async def disabled_docs():
            raise HTTPException(status_code=404, detail="Documentation not available")

    else:
        app = FastAPI(
            title="Secure API",
            docs_url=None,
            redoc_url=None,
            openapi_url=None
        )

        openapi_schema = get_openapi(
            title="Secure API",
            version="1.0.0",
            description="API with authentication and documentation protection",
            routes=app.routes,
        )

        app.openapi_schema = openapi_schema

        @app.get("/docs", include_in_schema=False)
        async def get_swagger_documentation(authenticated: bool = Depends(verify_docs_credentials)):
            return get_swagger_ui_html(
                openapi_url="/openapi.json",
                title=f"{app.title} - Swagger UI",
                swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
                swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
            )

        @app.get("/openapi.json", include_in_schema=False)
        async def get_open_api_endpoint(authenticated: bool = Depends(verify_docs_credentials)):
            return app.openapi_schema

        @app.get("/redoc", include_in_schema=False)
        async def get_redoc_documentation():
            raise HTTPException(status_code=404, detail="ReDoc documentation is disabled")

    return app

app = create_app()

@app.post("/register", status_code=status.HTTP_201_CREATED, response_model=dict)
async def register(user: User):
    """
    Регистрация нового пользователя.
    """
    if get_user(user.username) is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    hashed_password = hash_password(user.password)
    user_in_db = UserInDB(
        username=user.username,
        password=user.password,
        hashed_password=hashed_password
    )
    fake_users_db[user.username] = user_in_db
    return {"message": f"User '{user.username}' successfully registered"}


@app.get("/login")
async def login(authenticated_user: UserInDB = Depends(auth_user)):
    """
    Аутентификация пользователя.
    """
    return {"message": f"Welcome, {authenticated_user.username}!"}

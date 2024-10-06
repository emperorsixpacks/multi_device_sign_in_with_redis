# Settign up redis connnection
import os
import secrets
from dotenv import load_dotenv
from redis import Redis

load_dotenv(".env")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")

redis_client = Redis(REDIS_HOST, int(REDIS_PORT))


# Setting up demo user
from typing import List
from uuid import uuid4, UUID
import json
from datetime import datetime, timedelta
from dataclasses import dataclass, field


def now_date_time_to_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def generate_new_device_id():
    return str(uuid4())


def create_new_session_id():
    return secrets.token_urlsafe(16)


@dataclass
class Session:
    session_id: str = field(default_factory=create_new_session_id)
    device_name: str = field(default=None)
    ip_address: str = field(default=None)
    device_id: str = field(default_factory=generate_new_device_id)

    date_created: datetime = field(default_factory=now_date_time_to_str)


@dataclass
class User:
    username: str = field(default=None)
    email: str = field(default=None)
    password: str = field(default=None)
    bio: str = field(default=None)
    sessions: List[Session] | None = None

    @property
    def __dict__(self):
        return {
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "bio": self.bio,
            "sessions": self.return_session_dict(),
        }

    def return_session_dict(self):
        try:
            return [session.__dict__ for session in self.sessions]
        except AttributeError:
            return [session for session in self.sessions]


def return_user_from_db(username) -> User | None:
    with open("demo_users.json", "r", encoding="utf-8") as file:
        user = json.load(file).get(str(username), None)
        return User(**user) or None


def authenticate_user(username, password) -> bool | None:
    user = return_user_from_db(username=username)
    if not password == user.password:
        return None
    return user


def get_user_from_cache(userid) -> User | None:
    user = redis_client.get(name=userid)
    return User(**json.loads(user)) or None


def get_sessions(userid) -> List[Session] | None:
    user_sessions = get_user_from_cache(userid=userid).sessions

    if user_sessions is None:  # This is the users first time logging in
        return None

    return [Session(**session) for session in user_sessions] or None

def get_single_session(userid, session_id) -> Session | None:
    user_sessions = get_sessions(userid=userid)

    return next((session for session in user_sessions if session.session_id == session_id), None)

def update_user_cache(userid, new_data: User) -> User:
    
    user = return_user_from_db(username=userid)

    if user is None:
        return None

    redis_client.set(userid, json.dumps(new_data.__dict__))

    return new_data


def delete_session(userid, session_id) -> bool | None:
    user = get_user_from_cache(userid=userid)

    if user is None:
        return None
    session = get_single_session(userid=userid, session_id=session_id)
    if session is None:
        return None
    user.sessions.remove(
        next((session for session in user.sessions if session['session_id'] == session_id), None)
    )
    update_user_cache(userid=userid, new_data=user)
    return True


# Handling JWT tokens
import jwt
from jwt.exceptions import ExpiredSignatureError

SECRET = "8da6dcc9ce05b5ac4c04e5f9b9e6bdb2a2ad32bf8de05ce83b3711f982770c6f"
ACCESS_TOKEN_TTL_DAYS = 2


@dataclass
class Token:
    session_id: str = field(default=None)
    user: str = field(default=None)


def create_token(data: Token):
    to_encode = data.__dict__
    token_ttl_expire = datetime.now() + timedelta(days=ACCESS_TOKEN_TTL_DAYS)
    to_encode.update({"exp": token_ttl_expire})
    encoded_jwt = jwt.encode(to_encode, SECRET, algorithm="HS256")
    return encoded_jwt


def decode_token(payload) -> Token:
    try:
        data = jwt.decode(payload, SECRET, algorithms=["HS256"])
    except ExpiredSignatureError:
        return None
    token = Token(user=data["user"], session_id=data["session_id"])
    return token

    


# Setting up server
from typing import Annotated
from fastapi import FastAPI, Form, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security.utils import get_authorization_scheme_param

# Setting up user login form


@dataclass
class LoginForm:
    username: str = Form()
    password: str = Form()


app = FastAPI(
    name="Multi device sign in with Redis",
    description="Multi device sign in with Redis in stateless applications",
)


@app.get("/")
def index_route():
    return JSONResponse(content={"Message": "hello, this seems to be working :)"})


@app.post("/login")
def login_route(form: Annotated[LoginForm, Depends()], request: Request):
    username = form.username
    password = form.password
    user = authenticate_user(username, password)
    if user is None:
        return JSONResponse(
            status_code=404, content={"message": "Invalid ssername or password"}
        )
    session = Session(
        device_name=request.headers.get("User-Agent"), ip_address=request.client.host
    )
    user_from_cache = get_user_from_cache(username)

    if user_from_cache is None:
        return JSONResponse(content={"message": "one minute"}, status_code=404)

    user_sessions = get_sessions(userid=username)
    try:
        user_sessions.append(session)
    except AttributeError:
        user_sessions = [session]

    user_from_cache.sessions = user_sessions
    update_user_cache(userid=username, new_data=user_from_cache)

    token = create_token(Token(user=username, session_id=session.session_id))
    return JSONResponse(content={"message": "logged in", "token": token})


@app.get("/me")
def get_user(request : Request):
    _, token = get_authorization_scheme_param(request .headers.get("Authorization"))
    payload = decode_token(token)
    if payload is None:
        return JSONResponse(content={"message": "Invalid token"}, status_code=404)
    if get_single_session(userid=payload.user, session_id=payload.session_id) is None or get_user_from_cache(
        userid=payload.user) is None:
        return JSONResponse(content={"message": "Invalid token"}, status_code=404) 
    return JSONResponse(content=get_user_from_cache(payload.user).__dict__)


@app.post("/logout")
def logout_route(request: Request):
    
    _, token = get_authorization_scheme_param(request .headers.get("Authorization"))
    payload = decode_token(token)
    if payload is None:
        return JSONResponse(content={"message": "Invalid token"}, status_code=404)
    if get_single_session(userid=payload.user, session_id=payload.session_id) is None or get_user_from_cache(
        userid=payload.user) is None:
        return JSONResponse(content={"message": "Invalid token"}, status_code=404) 
    delete_session(payload.user, payload.session_id)
    return JSONResponse(content={"message": "logged out"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True, use_colors=True)

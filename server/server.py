# Settign up redis connnection
import os
from dotenv import load_dotenv
from redis import Redis

load_dotenv(".env")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")

redis_client = Redis(REDIS_HOST, int(REDIS_PORT))


# Setting up demo user
import json
from uuid import UUID, uuid4
from datetime import datetime
from dataclasses import dataclass, field


def return_user_from_db(user_id):
    with open("demo_users.json", "r", encoding="utf-8") as file:
        return json.load(file).get(str(user_id), None)


def now_date_time_to_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class Base:

    @property
    def _dict(self):
        return {
            key: value
            for key, value in self.__dict__.items()
            if not str(key).startswith("_")
        }


@dataclass
class Devices(Base):
    device_name: str
    ip_address: str
    session_id: UUID = field(default_factory=uuid4)
    date_time: str = field(default=now_date_time_to_str)


@dataclass
class UserSchema(Base):
    username: str
    email: str
    password: str
    bio: str
    devices: Devices | None = None


# Setting up server
from fastapi import FastAPI

app = FastAPI(
    name="Multi device sign in with Redis",
    description="Multi device sign in with Redis in stateless applications",
)

if __name__ == "__main__":

    print(UserSchema(**return_user_from_db(1)))
    # import uvicorn

    # uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True, use_colors=True)

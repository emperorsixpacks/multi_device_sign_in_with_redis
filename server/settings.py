import os
from typing import Optional, Dict
from pathlib import Path
import dotenv


def load_env_file(env_file: Path):
    dotenv.load_dotenv(env_file)



class BaseConfig:
    _env_file: Path = ".env"
    _env_file_variables: Dict[str, any] = False

    def __init_subclass__(cls):
        for attrs in cls.__


    @classmethod
    def _dict(cls):
        return {
            key: value
            for key, value in cls.__dict__.items()
            if not str(key).startswith("_")
        }
    
    @classmethod
    def return_env_file_value(cls):
        return  {
            key: os.getenv(key)
            for key in cls._dict().keys
            if os.environ.get(key.upper(), None) is not None
        }

    def _return_key_values(self):
        for key, value in self._env_file_variables().items():
            if hasattr(self, key):
                setattr(self, key, value)
        return None


@dataclass
class RedisSettings(BaseConfig):
    host: str = field(default="localhost")
    port: int = field(default=6379)
    db: Optional[int] = field(default=0)
    password: Optional[str] = field(default=None)

    def __post__init(self):
        pass


if __name__ == "__main__":
    print(RedisSettings()._dict())

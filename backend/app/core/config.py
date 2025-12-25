from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MONGO_URL: str
    DB_NAME: str
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ALGORITHM: str = "HS256"

    # ✅ OpenAI
    OPENAI_API_KEY: str | None = None

    CORS_ORIGINS: str = "*"

    class Config:
        env_file = ".env"

settings = Settings()

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MONGO_USER: str = "admin"
    MONGO_PASSWORD: str = "secret"
    MONGO_HOST: str = "mongodb"
    MONGO_PORT: int = 27017
    MONGO_DB: str = "netaudit"
    SECRET_KEY: str = "changeme-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    @property
    def MONGO_URI(self) -> str:
        return (
            f"mongodb://{self.MONGO_USER}:{self.MONGO_PASSWORD}"
            f"@{self.MONGO_HOST}:{self.MONGO_PORT}/{self.MONGO_DB}"
            "?authSource=admin"
        )

    model_config = {"env_file": ".env"}

settings = Settings()

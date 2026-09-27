from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(\n        env_prefix="CONTROL_PLANE_",\n        env_file=".env",\n        env_file_encoding="utf-8",\n        extra="ignore",\n    )

    database_url: str = "sqlite:///./control_plane.db"
    internal_token: str = "local-dev-change-me"
    publisher_mode: str = "disabled"


settings = Settings()

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CONTROL_PLANE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite:///./control_plane.db"
    internal_token: str = "local-dev-change-me"
    publisher_mode: str = "disabled"
    quarantine_root: str = ".control-plane/quarantine"
    max_candidate_bundle_bytes: int = 50 * 1024 * 1024


settings = Settings()

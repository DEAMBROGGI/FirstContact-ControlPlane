from pydantic import SecretStr
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
    work_claim_lease_seconds: int = 4 * 60 * 60
    github_app_id: str = ""
    github_app_private_key_path: str = ""
    github_api_url: str = "https://api.github.com"
    remediation_project_number: int | None = None
    remediation_project_lifecycle_field: str = "Lifecycle"
    remediation_project_token: SecretStr = SecretStr("")
    remediation_thread_token: SecretStr = SecretStr("")
    codex_review_user_token: SecretStr = SecretStr("")
    codex_review_trigger_login: str = ""
    codex_review_mode: str = "disabled"
    codex_review_actors: str = ""
    github_webhook_secret: SecretStr = SecretStr("")
    github_webhook_max_payload_bytes: int = 1024 * 1024
    human_review_actors: str = ""


settings = Settings()

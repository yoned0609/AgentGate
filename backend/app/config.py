"""AgentGate configuration via environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Server
    debug: bool = False
    test_mode: bool = False
    host: str = "0.0.0.0"
    port: int = 8100

    # Proxy target
    google_calendar_base_url: str = "https://www.googleapis.com/calendar/v3"

    # Auth
    master_api_key: str = "ag_dev_change_me_in_production"

    # Policy
    policy_dir: str = "policies"

    # Audit
    audit_db_path: str = "audit.db"

    # Semantic Poka-yoke
    semantic_rules_dir: str = "semantic_rules"
    streaming_validation: bool = False  # Enable per-chunk streaming validation

    # CORS
    cors_origins: str = "http://localhost:3000,http://localhost:3001"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()

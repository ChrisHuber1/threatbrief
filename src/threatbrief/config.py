from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    database_url: str = "postgresql://threatbrief:threatbrief@localhost:5432/threatbrief"
    anthropic_api_key: str = ""
    huggingface_api_token: str = ""
    langsmith_api_key: str = ""
    langsmith_project: str = "threatbrief"

    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    classifier_model: str = "facebook/bart-large-mnli"
    summarizer_model: str = "facebook/bart-large-cnn"
    asr_model: str = "openai/whisper-base"

    chunk_size: int = 512
    chunk_overlap: int = 64
    top_k_retrieval: int = 10


settings = Settings()

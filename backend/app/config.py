import os
from pathlib import Path
from pydantic import BaseModel
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

class Settings(BaseModel):
    APP_NAME: str = "AI Network Attack Forecasting System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Database Configuration (MySQL with SQLite fallback)
    # Example MySQL URL: mysql+pymysql://root:password@localhost:3306/network_attacks
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        f"sqlite:///{BASE_DIR / 'network_attacks.db'}"
    )
    
    # Model Artifact Paths
    MODELS_DIR: Path = BASE_DIR / "models"
    MODEL_PATH: Path = MODELS_DIR / "model.joblib"
    SCALER_PATH: Path = MODELS_DIR / "scaler.joblib"
    LABEL_ENCODER_PATH: Path = MODELS_DIR / "label_encoder.joblib"
    FEATURE_COLUMNS_PATH: Path = MODELS_DIR / "feature_columns.json"
    
    # Sample Data Path
    DATA_DIR: Path = BASE_DIR / "data"
    SAMPLE_TEST_CSV: Path = DATA_DIR / "sample_cicids2018_test.csv"
    
    # Time-window Forecasting Settings
    WINDOW_SIZE_FLOWS: int = 15
    RISK_THRESHOLD_MEDIUM: float = 30.0
    RISK_THRESHOLD_HIGH: float = 70.0

settings = Settings()

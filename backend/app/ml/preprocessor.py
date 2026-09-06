"""
Traffic Data Preprocessor for CIC-IDS2018 Features
"""

import json
import numpy as np
import pandas as pd
from app.config import settings

def load_feature_columns():
    if settings.FEATURE_COLUMNS_PATH.exists():
        with open(settings.FEATURE_COLUMNS_PATH, "r") as f:
            return json.load(f)
    # Default standard feature list if JSON artifact not generated yet
    from ml_pipeline.train_model import FEATURE_COLUMNS
    return FEATURE_COLUMNS

def preprocess_dataframe(df: pd.DataFrame, feature_columns: list) -> pd.DataFrame:
    """Clean, impute, and extract exact features required by the ML model."""
    df_clean = df.copy()

    # Normalize column names: strip spaces, handle variations
    col_mapping = {col: col.strip() for col in df_clean.columns}
    df_clean.rename(columns=col_mapping, inplace=True)

    # Standardize common variations if present
    var_aliases = {
        "Destination Port": "Dst Port",
        "Total Fwd Packets": "Tot Fwd Pkts",
        "Total Backward Packets": "Tot Bwd Pkts",
        "Total Length of Fwd Packets": "TotLen Fwd Pkts",
        "Total Length of Bwd Packets": "TotLen Bwd Pkts",
        "Flow Bytes/s": "Flow Byts/s",
        "Flow Packets/s": "Flow Pkts/s",
    }
    df_clean.rename(columns=var_aliases, inplace=True)

    # Ensure all required features exist, filling missing with 0
    for col in feature_columns:
        if col not in df_clean.columns:
            df_clean[col] = 0.0

    # Subset to model features
    df_features = df_clean[feature_columns].copy()

    # Replace inf and -inf with NaN, then fillna with column medians or 0
    df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_features.fillna(0.0, inplace=True)

    return df_features

"""
ML Model Training Pipeline for Network Attack Classification & Forecasting
Trains a calibrated Random Forest Classifier on CIC-IDS2018 network flow features.
Saves model, scaler, label encoder, and feature column list for low-latency inference.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from generate_dataset import generate_dataset, generate_sample_test_traffic

# Standard numerical features from CIC-IDS2018 used for flow classification
FEATURE_COLUMNS = [
    "Dst Port",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Bwd Pkt Len Mean",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Bwd IAT Tot",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "Down/Up Ratio",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts"
]

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Handle infinities, NaNs, and outliers in network flow records."""
    df = df.copy()
    
    # Replace inf and -inf with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Fill NaN with column median
    for col in FEATURE_COLUMNS:
        if col in df.columns:
            median_val = df[col].median()
            df[col] = df[col].fillna(median_val if not np.isnan(median_val) else 0.0)
            
    return df

def train():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(current_dir, "..", "data")
    models_dir = os.path.join(current_dir, "..", "models")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)
    
    train_csv = os.path.join(data_dir, "cicids2018_train.csv")
    test_sample_csv = os.path.join(data_dir, "sample_cicids2018_test.csv")
    
    # 1. Ensure dataset exists
    if not os.path.exists(train_csv):
        print("Generating training dataset...")
        generate_dataset(num_records=14000, output_csv=train_csv)
        
    if not os.path.exists(test_sample_csv):
        print("Generating sample test sequence...")
        generate_sample_test_traffic(test_sample_csv)
        
    print(f"Loading training data from {train_csv}...")
    df = pd.read_csv(train_csv)
    df = clean_data(df)
    
    # 2. Extract X and y
    available_features = [col for col in FEATURE_COLUMNS if col in df.columns]
    X = df[available_features]
    y = df["Label"]
    
    # 3. Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # 4. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded
    )
    
    # 5. Fit Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 6. Train Model: Random Forest
    # RATIONALE:
    # 1. Non-linear decision boundaries: Network attack patterns exhibit intricate multi-feature thresholding.
    # 2. High robustness to collinearity and outliers common in packet rate and IAT distributions.
    # 3. Well-calibrated class probability distributions (predict_proba) vital for proactive risk scoring & forecasting.
    # 4. Sub-millisecond inference latency per flow suitable for real-time SOC streaming.
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=18,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)
    
    # 7. Evaluate
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    target_names = [str(c) for c in label_encoder.classes_]
    report = classification_report(y_test, y_pred, target_names=target_names)
    
    print("\n" + "="*50)
    print(f"Model Accuracy: {acc * 100:.2f}%")
    print("="*50)
    print("Classification Report:")
    print(report)
    print("="*50)
    
    # 8. Save Artifacts
    model_path = os.path.join(models_dir, "model.joblib")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    encoder_path = os.path.join(models_dir, "label_encoder.joblib")
    features_path = os.path.join(models_dir, "feature_columns.json")
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, encoder_path)
    with open(features_path, "w") as f:
        json.dump(available_features, f, indent=2)
        
    print(f"Model saved to: {model_path}")
    print(f"Scaler saved to: {scaler_path}")
    print(f"Label encoder saved to: {encoder_path}")
    print(f"Feature columns saved to: {features_path}")
    print("Training completed successfully!")

if __name__ == "__main__":
    train()

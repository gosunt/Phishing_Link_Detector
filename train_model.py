# train_model.py
from ml_based import MLDetector
import pandas as pd
import os

# Create sample training data
def create_sample_data():
    data = {
        'url': [
            'https://www.google.com',
            'https://www.paypal.com/login',
            'http://phishing-site.com/verify',
            'https://www.amazon.com',
            'http://fake-bank.com/account',
            'https://www.github.com',
            'http://steal-info.com/login.php',
            'https://www.microsoft.com'
        ],
        'label': [0, 0, 1, 0, 1, 0, 1, 0]  # 0=legitimate, 1=phishing
    }
    return pd.DataFrame(data)

def train_and_save_model():
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Create sample data
    data = create_sample_data()
    
    # Initialize and train model
    detector = MLDetector()
    print("Training model...")
    accuracy = detector.train_model(data, 'models/phishing_model.pkl')
    print(f"Model trained successfully! Accuracy: {accuracy:.2f}")

if __name__ == "__main__":
    train_and_save_model()
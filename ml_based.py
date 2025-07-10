import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
from urllib.parse import urlparse
import re

class MLDetector:  # This class name must match exactly with the import
    def __init__(self, model_path=None):
        self.features = [
            'url_length', 'num_dots', 'num_hyphens', 'num_underscore',
            'num_slash', 'num_question', 'num_equal', 'num_at',
            'num_exclamation', 'has_ip', 'has_https', 'shortening_service'
        ]
        self.model = joblib.load(model_path) if model_path else None
        
    def extract_features(self, url):
        features = {}
        
        # URL length
        features['url_length'] = len(url)
        
        # Count special characters
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscore'] = url.count('_')
        features['num_slash'] = url.count('/')
        features['num_question'] = url.count('?')
        features['num_equal'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_exclamation'] = url.count('!')
        
        # Check for IP address
        domain = urlparse(url).netloc
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['has_ip'] = 1 if re.match(ip_pattern, domain) else 0
        
        # Check for HTTPS
        features['has_https'] = 1 if url.startswith('https') else 0
        
        # Check for URL shortening
        shortening_services = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly']
        features['shortening_service'] = 0
        for service in shortening_services:
            if service in url:
                features['shortening_service'] = 1
                break
                
        return pd.DataFrame([features])
    
    def train_model(self, data_path, save_path='models/phishing_model.pkl'):
        data = pd.read_csv(data_path)
        
        # Extract features
        X = pd.DataFrame(columns=self.features)
        y = data['label']
        
        for url in data['url']:
            features = self.extract_features(url)
            X = pd.concat([X, features], ignore_index=True)
            
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42)
            
        # Train model
        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(X_train, y_train)
        
        # Evaluate
        preds = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, preds)
        
        # Save model
        joblib.dump(self.model, save_path)
        
        return accuracy
    
    def predict_url(url):
	    return 1 

        
    # In ml_based.py, modify the __init__ method:
    def __init__(self, model_path=None):
     self.features = [
        'url_length', 'num_dots', 'num_hyphens', 'num_underscore',
        'num_slash', 'num_question', 'num_equal', 'num_at',
        'num_exclamation', 'has_ip', 'has_https', 'shortening_service'
     ]
     self.model = None
     if model_path:
        try:
            self.model = joblib.load(model_path)
        except:
            print("Warning: Could not load model, running without ML detection")
            self.model = None
# Phishing_Link_Detector

## Description

The Phishing URL Detector is a comprehensive security tool that analyzes websites for potential phishing threats using multiple detection methods:

### Key Features:
- **Multi-layered detection** combining rule-based and machine learning approaches
- **Google Safe Browsing API integration** for real-time threat intelligence
- **Detailed analysis** with visual risk indicators
- **Historical tracking** of scanned URLs
- **Customizable settings** including API key configuration

The system evaluates URLs based on:
- Suspicious patterns (IP addresses, @ symbols, long URLs)
- Domain characteristics (TLDs, subdomains, brand spoofing)
- Machine learning predictions (when model available)
- Google's database of known malicious sites

## System Components

1. **gui_app.py**: Main application with graphical interface
2. **rule_based.py**: Rule-based detection engine
3. **ml_based.py**: Machine learning classifier
4. **train_model.py**: Script to train the ML model
5. **legitimate_urls.csv**: Sample training data

## Installation

1. Install required dependencies:
```bash
pip install scikit-learn pandas joblib requests python-dotenv
```

2. For Google Safe Browsing API:
- Obtain an API key from [Google Cloud Console](https://console.cloud.google.com/)
- Add it to `.env` file:
```
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
```

## Usage

### Running the Application
```bash
python gui_app.py
```

### Main Interface Features:
1. **URL Analysis**:
   - Enter any URL in the text field
   - Click "Check URL" or press Enter
   - View comprehensive results across multiple tabs

2. **Results Tabs**:
   - **Summary**: Overall risk assessment
   - **Rule Analysis**: Detailed rule-based findings
   - **Machine Learning**: Model predictions (if available)
   - **History**: Previous scan records

3. **Additional Functions**:
   - ⚙️ Settings: Configure API keys
   - ? Help: View usage instructions
   - Generate: Create secure password suggestions

### Training the ML Model (Optional)
To train or retrain the machine learning model:
```bash
python train_model.py
```
This creates/updates `models/phishing_model.pkl`

## OUTPUT

<img width="1127" height="915" alt="Image" src="https://github.com/user-attachments/assets/4ddec08f-e2a8-4a8d-ad4a-578aa753f8d7" />


## Technical Notes

- The rule-based system checks for 8+ suspicious characteristics
- Machine learning model uses 12 URL features for classification
- Google Safe Browsing API provides enterprise-grade threat data
- All processing occurs locally after initial API checks

## Security Considerations

- Always verify suspicious URLs through multiple channels
- The tool is not a replacement for comprehensive security solutions
- Google API queries are rate-limited (max ~10,000 requests/day)

For best results, combine with other security measures like:
- Browser security extensions
- Email filtering solutions
- User security awareness training

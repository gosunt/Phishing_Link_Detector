import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from rule_based import RuleBasedDetector
from ml_based import MLDetector
import requests
import json
import time
import os
import webbrowser
from datetime import datetime

class PhishingDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing URL Detector v2.0")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        
        # Initialize detectors
        self.rule_detector = RuleBasedDetector()  # FIXED: Added parentheses to create instance
        self.ml_detector = self.initialize_ml_detector()
        
        # Google Safe Browsing API key
        self.api_key = self.load_api_key()
        
        # History tracking
        self.history = []
        self.max_history = 20
        
        self.create_widgets()
        self.add_text_tags()
    
    def initialize_ml_detector(self):
        """Initialize ML detector with error handling"""
        try:
            if os.path.exists('models/phishing_model.pkl'):
                return MLDetector('models/phishing_model.pkl')
            return None
        except Exception as e:
            messagebox.showwarning("ML Model Error", 
                                 f"Could not load ML model: {str(e)}\nRunning without ML detection.")
            return None
    
    def load_api_key(self):
        """Load API key from environment or file"""
        try:
            from dotenv import load_dotenv
            load_dotenv()
            return os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
        except:
            return ''
    
    def add_text_tags(self):
        """Configure text colors and styles for the results display"""
        self.summary_text.tag_config('danger', foreground='red', font=('Arial', 10, 'bold'))
        self.summary_text.tag_config('warning', foreground='orange', font=('Arial', 10, 'bold'))
        self.summary_text.tag_config('safe', foreground='green', font=('Arial', 10, 'bold'))
        self.summary_text.tag_config('header', font=('Arial', 11, 'bold'))
        self.summary_text.tag_config('normal', font=('Arial', 10))
        
        self.rule_text.tag_config('alert', foreground='red')
        self.rule_text.tag_config('warning', foreground='orange')
        self.rule_text.tag_config('normal', foreground='black')
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Phishing URL Detector", style='Header.TLabel').pack(side=tk.LEFT)
        
        # Settings button
        settings_btn = ttk.Button(header_frame, text="⚙️", width=3, 
                                command=self.show_settings)
        settings_btn.pack(side=tk.RIGHT, padx=5)
        
        # Help button
        help_btn = ttk.Button(header_frame, text="?", width=3, 
                            command=self.show_help)
        help_btn.pack(side=tk.RIGHT)
        
        # URL Entry frame
        url_frame = ttk.Frame(main_frame)
        url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(url_frame, text="Enter URL to analyze:").pack(side=tk.LEFT)
        
        self.url_entry = ttk.Entry(url_frame, width=70)
        self.url_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.url_entry.bind('<Return>', lambda e: self.check_url())
        
        # Check Button
        check_btn = ttk.Button(url_frame, text="Check URL", command=self.check_url)
        check_btn.pack(side=tk.LEFT)
        
        # Results Notebook (Tabs)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary Tab
        summary_tab = ttk.Frame(self.notebook)
        self.summary_text = scrolledtext.ScrolledText(
            summary_tab, height=10, wrap=tk.WORD, font=('Arial', 10))
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.summary_text.config(state=tk.DISABLED)
        
        # Rule-Based Tab
        rule_tab = ttk.Frame(self.notebook)
        self.rule_text = scrolledtext.ScrolledText(
            rule_tab, height=10, wrap=tk.WORD, font=('Arial', 10))
        self.rule_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.rule_text.config(state=tk.DISABLED)
        
        # ML Tab (if model available)
        if self.ml_detector:
            ml_tab = ttk.Frame(self.notebook)
            self.ml_text = scrolledtext.ScrolledText(
                ml_tab, height=10, wrap=tk.WORD, font=('Arial', 10))
            self.ml_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.ml_text.config(state=tk.DISABLED)
            self.notebook.add(ml_tab, text="Machine Learning")
        
        # History Tab
        history_tab = ttk.Frame(self.notebook)
        self.history_text = scrolledtext.ScrolledText(
            history_tab, height=10, wrap=tk.WORD, font=('Arial', 10))
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.history_text.config(state=tk.DISABLED)
        
        # Add tabs to notebook
        self.notebook.add(summary_tab, text="Summary")
        self.notebook.add(rule_tab, text="Rule Analysis")
        self.notebook.add(history_tab, text="History")
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready to analyze URLs")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                             relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def show_settings(self):
        """Show settings dialog"""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Settings")
        settings_win.geometry("400x300")
        
        ttk.Label(settings_win, text="Google Safe Browsing API Key:").pack(pady=(10, 0))
        
        api_frame = ttk.Frame(settings_win)
        api_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.api_key_entry = ttk.Entry(api_frame)
        self.api_key_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.api_key_entry.insert(0, self.api_key)
        
        ttk.Button(api_frame, text="Save", 
                  command=lambda: self.save_api_key(self.api_key_entry.get())).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(settings_win, text="Detection Settings:", font=('Arial', 10, 'bold')).pack(pady=(20, 5))
        
        # Add more settings here as needed
    
    def save_api_key(self, key):
        """Save API key to environment"""
        self.api_key = key.strip()
        try:
            with open('.env', 'w') as f:
                f.write(f"GOOGLE_SAFE_BROWSING_API_KEY={self.api_key}")
            messagebox.showinfo("Success", "API key saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save API key: {str(e)}")
    
    def show_help(self):
        """Show help information"""
        help_text = """Phishing URL Detector Help:

1. Enter a URL in the text box and click 'Check URL'
2. View results in the different tabs:
   - Summary: Overall assessment
   - Rule Analysis: Detailed rule-based results
   - Machine Learning: ML model prediction (if available)
   - History: Previous scan results

3. Settings:
   - Configure Google Safe Browsing API key
   
Note: For best results, obtain a Google Safe Browsing API key from:
https://developers.google.com/safe-browsing
"""
        messagebox.showinfo("Help", help_text)
    
    def check_google_safe_browsing(self, url):
        """Check URL against Google Safe Browsing API"""
        if not self.api_key:
            return False, []
            
        payload = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            response = requests.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={'key': self.api_key},
                json=payload,
                timeout=5
            )
            response.raise_for_status()
            
            result = response.json()
            if 'matches' in result:
                threats = [match['threatType'] for match in result['matches']]
                return True, threats
            return False, []
            
        except Exception as e:
            print(f"Safe Browsing API Error: {str(e)}")
            return False, []
    
    def check_url(self):
        """Perform comprehensive URL check"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        # Add http:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        self.status_var.set(f"Analyzing URL: {url}...")
        self.root.update()
        
        try:
            # Clear previous results
            for widget in [self.summary_text, self.rule_text]:
                widget.config(state=tk.NORMAL)
                widget.delete(1.0, tk.END)
            if hasattr(self, 'ml_text'):
                self.ml_text.config(state=tk.NORMAL)
                self.ml_text.delete(1.0, tk.END)
            
            # Check Google Safe Browsing
            is_dangerous, threats = self.check_google_safe_browsing(url)
            time.sleep(1)  # Rate limiting
            
            # Check with rule-based detector
            rule_result, rule_score, rule_alerts = self.rule_detector.check_url(url)
            
            # Check with ML detector if available
            ml_result, ml_prob = None, None
            if self.ml_detector:
                try:
                    ml_result, ml_prob = self.ml_detector.predict(url)
                except Exception as e:
                    print(f"ML Prediction Error: {str(e)}")
            
            # Add to history
            self.add_to_history(url, is_dangerous, rule_result, ml_result)
            
            # Display results
            self.display_results(url, is_dangerous, threats, 
                               rule_result, rule_score, rule_alerts, 
                               ml_result, ml_prob)
            
            self.status_var.set(f"Analysis complete - {datetime.now().strftime('%H:%M:%S')}")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error occurred during analysis")
    
    def add_to_history(self, url, is_dangerous, rule_result, ml_result):
        """Add current scan to history"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        result = "Malicious" if is_dangerous else rule_result.split()[0]
        
        if ml_result:
            result += f" | ML: {ml_result.split()[0]}"
        
        self.history.insert(0, (timestamp, url, result))
        
        # Keep only last N items
        if len(self.history) > self.max_history:
            self.history = self.history[:self.max_history]
        
        # Update history display
        self.history_text.config(state=tk.NORMAL)
        self.history_text.delete(1.0, tk.END)
        
        for idx, (ts, u, res) in enumerate(self.history):
            self.history_text.insert(tk.END, f"{ts} - {res}\n")
            self.history_text.insert(tk.END, f"{u}\n")
            if idx < len(self.history) - 1:
                self.history_text.insert(tk.END, "-"*50 + "\n")
        
        self.history_text.config(state=tk.DISABLED)
    
    def display_results(self, url, is_dangerous, threats, 
                      rule_result, rule_score, rule_alerts, 
                      ml_result, ml_prob):
        """Display results in the GUI"""
        # Summary Tab
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        
        self.summary_text.insert(tk.END, "=== URL Safety Summary ===\n\n", 'header')
        
        # Google Safe Browsing results
        if is_dangerous:
            self.summary_text.insert(tk.END, 
                f"🚨 DANGEROUS (Google Safe Browsing): {', '.join(threats)}\n\n",
                'danger')
        else:
            self.summary_text.insert(tk.END, 
                "✅ Not in Google's list of known dangerous sites\n\n",
                'safe')
        
        # Rule-Based results
        if "High probability" in rule_result:
            self.summary_text.insert(tk.END, 
                f"🚨 Rule-Based: {rule_result} (Score: {rule_score:.1f}/5)\n",
                'danger')
        elif "Suspicious" in rule_result:
            self.summary_text.insert(tk.END, 
                f"⚠️ Rule-Based: {rule_result} (Score: {rule_score:.1f}/5)\n",
                'warning')
        else:
            self.summary_text.insert(tk.END, 
                f"✅ Rule-Based: {rule_result} (Score: {rule_score:.1f}/5)\n",
                'safe')
        
        # ML results if available
        if ml_result:
            if "High probability" in ml_result:
                self.summary_text.insert(tk.END, 
                    f"\n🚨 ML Detection: {ml_result} (Probability: {ml_prob:.1%})",
                    'danger')
            elif "Suspicious" in ml_result:
                self.summary_text.insert(tk.END, 
                    f"\n⚠️ ML Detection: {ml_result} (Probability: {ml_prob:.1%})",
                    'warning')
            else:
                self.summary_text.insert(tk.END, 
                    f"\n✅ ML Detection: {ml_result} (Probability: {ml_prob:.1%})",
                    'safe')
        
        # Add final recommendation
        self.summary_text.insert(tk.END, "\n\n=== Final Recommendation ===\n", 'header')
        
        if is_dangerous or "High probability" in rule_result:
            self.summary_text.insert(tk.END, 
                "\n🚨 DO NOT VISIT THIS SITE - High phishing risk detected!\n", 
                'danger')
        elif "Suspicious" in rule_result:
            self.summary_text.insert(tk.END, 
                "\n⚠️ Be very cautious with this site - multiple suspicious indicators found\n",
                'warning')
        else:
            self.summary_text.insert(tk.END, 
                "\n✅ This site appears to be safe based on our analysis\n",
                'safe')
        
        self.summary_text.config(state=tk.DISABLED)
        
        # Rule-Based Details Tab
        self.rule_text.config(state=tk.NORMAL)
        self.rule_text.delete(1.0, tk.END)
        
        self.rule_text.insert(tk.END, "=== Rule-Based Analysis Details ===\n\n", 'header')
        self.rule_text.insert(tk.END, f"URL: {url}\n\n")
        self.rule_text.insert(tk.END, f"Total Risk Score: {rule_score:.1f}/5\n\n")
        
        if rule_alerts:
            self.rule_text.insert(tk.END, "Detected Issues:\n", 'header')
            for alert in rule_alerts:
                if "serious" in alert.lower() or "red flag" in alert.lower():
                    self.rule_text.insert(tk.END, f"• {alert}\n", 'alert')
                elif "suspicious" in alert.lower() or "caution" in alert.lower():
                    self.rule_text.insert(tk.END, f"• {alert}\n", 'warning')
                else:
                    self.rule_text.insert(tk.END, f"• {alert}\n", 'normal')
        else:
            self.rule_text.insert(tk.END, "No suspicious characteristics detected\n", 'safe')
        
        self.rule_text.config(state=tk.DISABLED)
        
        # ML Details Tab if available
        if hasattr(self, 'ml_text') and ml_result:
            self.ml_text.config(state=tk.NORMAL)
            self.ml_text.delete(1.0, tk.END)
            
            self.ml_text.insert(tk.END, "=== Machine Learning Analysis ===\n\n", 'header')
            self.ml_text.insert(tk.END, f"Phishing Probability: {ml_prob:.1%}\n\n")
            
            if ml_prob > 0.7:
                self.ml_text.insert(tk.END, "Interpretation: High confidence of phishing\n", 'alert')
            elif ml_prob > 0.4:
                self.ml_text.insert(tk.END, "Interpretation: Moderate chance of phishing\n", 'warning')
            else:
                self.ml_text.insert(tk.END, "Interpretation: Likely legitimate\n", 'safe')
            
            self.ml_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    try:
        app = PhishingDetectorApp(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"The application crashed: {str(e)}")
        raise e
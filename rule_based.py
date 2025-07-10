import re
from urllib.parse import urlparse

class RuleBasedDetector:
    def __init__(self):
        self.suspicious_brands = [
            "amazon", "paypal", "apple", "google", "microsoft", "facebook",
            "netflix", "bankofamerica", "instagram", "linkedin", "youtube"
        ]
        self.suspicious_tlds = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq"]
        self.shortening_services = ["bit.ly", "goo.gl", "tinyurl", "ow.ly"]

    def check_url(self, url):
        domain = self.extract_domain(url)
        score = 0
        alerts = []

        # IP Address Check
        if self.has_ip_address(url):
            score += 1
            alerts.append("IP address used instead of domain name")
            
        # '@' Symbol Check
        if self.has_at_symbol(url):
            score += 2  # Higher weight as it's a serious red flag
            alerts.append("'@' symbol in URL (serious red flag)")
            
        # URL Length Check
        if self.is_long_url(url):
            score += 1
            alerts.append("URL is very long (potential obfuscation)")
            
        # Subdomain Check
        if self.has_many_subdomains(domain):
            score += 1
            alerts.append("Too many subdomains detected")
            
        # Suspicious TLD Check
        if self.has_suspicious_tld(domain):
            score += 1
            alerts.append("Suspicious TLD detected")
            
        # Brand Spoofing Check
        if self.has_fake_brand_subdomain(domain):
            score += 1
            alerts.append("Spoofed brand in subdomain")
            
        # URL Shortening Service Check
        if self.is_shortened_url(url):
            score += 1
            alerts.append("URL shortening service detected")
            
        # HTTPS Check
        if not url.startswith('https'):
            score += 1
            alerts.append("Not using HTTPS (insecure connection)")

        # Determine threat level with adjusted thresholds
        if score >= 4:  # Increased threshold for high probability
            return "High probability of phishing", score, alerts
        elif score >= 2:  # Increased threshold for suspicious
            return "Suspicious URL - caution advised", score, alerts
        else:
            return "Likely legitimate", score, alerts

    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            domain = urlparse(url).netloc
            return domain.lower() if domain else ""
        except:
            return ""

    def has_ip_address(self, url):
        """Check if URL contains an IP address"""
        return bool(re.search(r"\d{1,3}(\.\d{1,3}){3}", url))

    def has_at_symbol(self, url):
        """Check if URL contains '@' symbol"""
        return "@" in url

    def is_long_url(self, url, threshold=75):
        """Check if URL exceeds length threshold"""
        return len(url) > threshold

    def has_many_subdomains(self, domain, threshold=3):
        """Check if domain has too many subdomains"""
        return domain.count('.') > threshold

    def has_suspicious_tld(self, domain):
        """Check if domain uses suspicious TLD"""
        return any(domain.endswith(tld) for tld in self.suspicious_tlds)

    def has_fake_brand_subdomain(self, domain):
        """Check for brand spoofing in subdomains"""
        for brand in self.suspicious_brands:
            if brand in domain and not domain.endswith(f"{brand}.com"):
                return True
        return False

    def is_shortened_url(self, url):
        """Check if URL uses shortening service"""
        return any(service in url for service in self.shortening_services)
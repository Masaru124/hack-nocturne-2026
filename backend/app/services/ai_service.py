"""
AIService - Core AI analysis logic
Provides scam detection using rule-based analysis and ML when available.
"""

import asyncio
import logging
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class AIService:
    """AI service for scam detection using rule-based analysis and ML models."""
    
    def __init__(self):
        self.model_loaded = False
        self._initialized = False
    
    async def initialize(self):
        """Initialize the AI service and load models if available."""
        if self._initialized:
            return
            
        try:
            # In a real implementation, you would load DistilBERT here
            # For now, we'll use rule-based analysis only
            logger.info("AIService initialized with rule-based analysis")
            self.model_loaded = False
        except Exception as e:
            logger.warning(f"Failed to load ML model, falling back to rules: {e}")
            self.model_loaded = False
        
        self._initialized = True
    
    async def analyze_message(self, text: str, url: str = "") -> Dict:
        """
        Analyze text and optional URL for scam indicators.
        
        Returns:
            {
                "scam_score": int (0-100),
                "risk_level": str ("SAFE" | "LOW_RISK" | "SUSPICIOUS" | "HIGH_RISK" | "SCAM"),
                "flagged_keywords": List[str],
                "flagged_urls": List[str],
                "explanation": str,
                "message_hash": str,
                "url_analysis": Dict,
                "ai_confidence": float,
                "timestamp": str
            }
        """
        if not self._initialized:
            await self.initialize()
        
        # Generate message hash
        message_hash = f"0x{hash(text + url) & 0xffffffffffffffff:016x}"
        
        # Analyze keywords
        scam_keywords = [
            "urgent", "immediate action required", "account suspended", 
            "verify now", "click here", "limited time", "act now",
            "congratulations", "winner", "free money", "guaranteed",
            "risk-free", "investment opportunity", "cryptocurrency",
            "bitcoin", "ethereum", "wallet", "private key"
        ]
        
        flagged_keywords = []
        text_lower = text.lower()
        for keyword in scam_keywords:
            if keyword in text_lower:
                flagged_keywords.append(keyword)
        
        # Analyze URLs
        flagged_urls = []
        url_analysis = {"status": "none", "message": "No URL provided"}
        
        if url:
            url_analysis = self._analyze_url(url)
            if url_analysis["status"] in ["scam", "suspicious", "caution"]:
                flagged_urls.append(url)
        
        # Calculate base scam score from keywords
        keyword_score = min(len(flagged_keywords) * 15, 60)
        
        # Add URL risk score
        url_score = 0
        if url_analysis["status"] == "scam":
            url_score = 30
        elif url_analysis["status"] == "suspicious":
            url_score = 20
        elif url_analysis["status"] == "caution":
            url_score = 10
        
        # Urgency and pressure tactics
        urgency_patterns = [
            r"\bimmediately\b", r"\burgent\b", r"\blast chance\b", 
            r"\blimited time\b", r"\bact now\b", r"\bdon't miss\b"
        ]
        urgency_score = sum(10 for pattern in urgency_patterns if re.search(pattern, text_lower))
        
        # Personal information requests
        info_patterns = [
            r"\bpassword\b", r"\bssn\b", r"\bsocial security\b",
            r"\bcredit card\b", r"\bbank account\b", r"\bprivate key\b"
        ]
        info_score = sum(15 for pattern in info_patterns if re.search(pattern, text_lower))
        
        # Calculate total scam score
        scam_score = min(keyword_score + url_score + urgency_score + info_score, 100)
        
        # Determine risk level
        if scam_score >= 80:
            risk_level = "SCAM"
        elif scam_score >= 60:
            risk_level = "HIGH_RISK"
        elif scam_score >= 40:
            risk_level = "SUSPICIOUS"
        elif scam_score >= 20:
            risk_level = "LOW_RISK"
        else:
            risk_level = "SAFE"
        
        # Generate explanation
        explanation = self._generate_explanation(
            scam_score, risk_level, flagged_keywords, flagged_urls, url_analysis
        )
        
        # AI confidence (higher when model is loaded, lower for rules only)
        ai_confidence = 0.8 if self.model_loaded else 0.6
        
        return {
            "scam_score": scam_score,
            "risk_level": risk_level,
            "flagged_keywords": flagged_keywords,
            "flagged_urls": flagged_urls,
            "explanation": explanation,
            "message_hash": message_hash,
            "url_analysis": url_analysis,
            "ai_confidence": ai_confidence,
            "timestamp": str(int(time.time()))
        }
    
    def _analyze_url(self, url: str) -> Dict:
        """Analyze a URL for suspicious indicators."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Suspicious domain patterns
            suspicious_patterns = [
                r".*tk$", r".*ml$", r".*ga$",  # free TLDs
                r".*\.bit$", r".*onion$",      # crypto/tor domains
                r".*secure.*login.*",          # fake secure sites
                r".*verify.*account.*",        # verification scams
                r".*paypal.*",                 # impersonation
                r".*[0-9]{3,}.*",             # domains with many numbers
            ]
            
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, domain):
                    return {
                        "status": "scam" if "paypal" in domain else "suspicious",
                        "message": f"Suspicious domain pattern detected: {domain}"
                    }
            
            # Check for HTTPS
            if parsed.scheme != "https":
                return {
                    "status": "caution",
                    "message": "URL does not use HTTPS encryption"
                }
            
            # Check for URL shorteners
            shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
            if any(shortener in domain for shortener in shorteners):
                return {
                    "status": "caution",
                    "message": "URL shortener detected - destination unknown"
                }
            
            return {
                "status": "safe",
                "message": "No obvious suspicious patterns detected"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to analyze URL: {str(e)}"
            }
    
    def _generate_explanation(self, scam_score: int, risk_level: str, 
                            flagged_keywords: List[str], flagged_urls: List[str],
                            url_analysis: Dict) -> str:
        """Generate a human-readable explanation of the analysis."""
        if risk_level == "SAFE":
            return "✅ This message appears to be safe with no obvious scam indicators."
        
        explanation_parts = []
        
        if flagged_keywords:
            explanation_parts.append(f"⚠️ Found suspicious keywords: {', '.join(flagged_keywords[:3])}")
        
        if flagged_urls:
            explanation_parts.append(f"🔗 Suspicious URL detected: {url_analysis['message']}")
        
        if scam_score >= 80:
            explanation_parts.append("🚨 High probability this is a scam - do not engage!")
        elif scam_score >= 60:
            explanation_parts.append("⚡ High risk - exercise extreme caution")
        elif scam_score >= 40:
            explanation_parts.append("🔍 Suspicious - verify through official channels")
        
        return " | ".join(explanation_parts)
    
    async def cleanup(self):
        """Clean up resources and unload models."""
        if self.model_loaded:
            # In a real implementation, you'd unload the ML model here
            logger.info("Cleaning up AIService resources")
        self._initialized = False
        self.model_loaded = False

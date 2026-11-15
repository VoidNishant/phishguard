"""
PhishGuard Detection Engine.
Combines Machine Learning predictions with Cybersecurity Heuristics
to compute an explainable, defense-in-depth risk score for any URL.
"""

import os
import re
import joblib
import pandas as pd
from urllib.parse import urlparse

from features import (
    extract_features,
    FEATURE_NAMES,
    normalize_url,
    extract_domain_components,
    is_ip_address
)
from heuristics import analyze_heuristics
import train_model

MODEL_FILE = "model.joblib"


class PhishGuardEngine:
    def __init__(self, model_path: str = MODEL_FILE):
        self.model_path = model_path
        self.package = None
        self.model = None
        self._load_or_train_model()

    def _load_or_train_model(self):
        """Loads existing model from disk, or automatically trains one if missing."""
        if not os.path.exists(self.model_path):
            print(f"Model file '{self.model_path}' not found. Training new model...")
            self.package = train_model.train_and_export_model(self.model_path)
        else:
            self.package = joblib.load(self.model_path)
            # Validate feature count matches current FEATURE_NAMES
            if len(self.package.get("feature_names", [])) != len(FEATURE_NAMES):
                print("Model feature mismatch detected. Retraining model...")
                self.package = train_model.train_and_export_model(self.model_path)
        self.model = self.package["model"]

    def dissect_url(self, raw_url: str) -> dict:
        """
        Breaks down a URL into its core structural components for inspection.
        Guaranteed safe against malformed inputs and port parsing exceptions.
        """
        clean = raw_url.strip()
        parsed_norm = normalize_url(clean)
        
        try:
            parsed = urlparse(parsed_norm)
            hostname = parsed.hostname or ""
            scheme = parsed.scheme or "http"
            path = parsed.path or "/"
            query = parsed.query or "(none)"
        except Exception:
            hostname = ""
            scheme = "unknown"
            path = "/"
            query = "(none)"

        # Safe port extraction
        try:
            port = str(parsed.port) if parsed.port is not None else ("443" if scheme == "https" else "80")
        except (ValueError, TypeError):
            port = "invalid"

        # Safe domain components using ccTLD-aware extractor
        subdomain, reg_domain, tld = extract_domain_components(hostname)

        return {
            "original_url": clean,
            "scheme": scheme,
            "hostname": hostname or "(no host detected)",
            "subdomain": subdomain if subdomain else "(none)",
            "registered_domain": reg_domain if reg_domain else "(none)",
            "tld": f".{tld}" if tld and tld != "(none - IP)" else (tld if tld else "(none)"),
            "path": path,
            "query": query,
            "port": port
        }

    def analyze(self, raw_url: str) -> dict:
        """
        Runs comprehensive cybersecurity analysis:
        1. Input validation & malformed URL guardrails
        2. Structural dissection
        3. Feature extraction
        4. Machine Learning inference
        5. Heuristic rules engine
        6. Calibrated hybrid risk score calculation
        """
        if not raw_url or not raw_url.strip():
            return {"error": "Empty URL provided. Please enter a valid URL."}

        clean_url = raw_url.strip()

        # Guardrail 1: Check for script execution / pseudo-protocols
        lower_raw = clean_url.lower()
        if lower_raw.startswith(("javascript:", "data:", "vbscript:", "file:")):
            heuristics_res = analyze_heuristics(clean_url)
            dissection = self.dissect_url(clean_url)
            return {
                "url": clean_url,
                "dissection": dissection,
                "verdict": "PHISHING / MALICIOUS",
                "risk_level": "Critical Risk",
                "theme_color": "danger",
                "badge_icon": "🚨",
                "summary_message": "CRITICAL THREAT: Execution pseudo-protocol detected! This URL attempts direct client-side script execution or payload rendering.",
                "composite_risk_score": 100.0,
                "ml_risk_score": 100.0,
                "heuristic_risk_score": 100,
                "triggered_rules": heuristics_res["triggered_rules"],
                "rules_checked": heuristics_res["rules_checked_count"],
                "rules_triggered": heuristics_res["rules_triggered_count"],
                "features": extract_features(clean_url)
            }

        # Guardrail 2: Hostname validation
        parsed_norm = normalize_url(clean_url)
        try:
            parsed = urlparse(parsed_norm)
            hostname = parsed.hostname
        except Exception:
            hostname = None

        if not hostname:
            return {
                "error": "Malformed URL: Unable to resolve a valid domain or IP address in the provided string."
            }

        # 1. Structural dissection
        dissection = self.dissect_url(clean_url)

        # 2. Lexical & Structural features
        features = extract_features(clean_url)

        # 3. Heuristic Analysis
        heuristics_result = analyze_heuristics(clean_url)
        heuristic_score = heuristics_result["rule_risk_score"]

        # 4. ML Inference
        df_feat = pd.DataFrame([features])[FEATURE_NAMES]
        ml_prob = float(self.model.predict_proba(df_feat)[0][1])  # Malicious probability
        ml_score = round(ml_prob * 100, 1)

        # 5. Composite Hybrid Risk Calculation
        # Check if any Critical heuristic triggered (e.g. Brand Spoofing, RFC @ trick, Homograph)
        has_critical = any(
            item["rule"].severity == "Critical"
            for item in heuristics_result["triggered_rules"]
        )

        if has_critical:
            # Deterministic override for verified malicious attack vectors
            composite_score = max(75.0, round(0.70 * heuristic_score + 0.30 * ml_score, 1))
        elif heuristic_score >= 40:
            # High certainty rule triggers
            composite_score = round(0.60 * heuristic_score + 0.40 * ml_score, 1)
        else:
            # Balanced blend
            composite_score = round(0.40 * heuristic_score + 0.60 * ml_score, 1)

        # Ensure composite is strictly bounded [0, 100]
        composite_score = max(0.0, min(100.0, composite_score))

        # 6. Calibrated Verdict Mapping
        if composite_score >= 55.0 or has_critical:
            verdict = "PHISHING / MALICIOUS"
            risk_level = "High Threat"
            theme_color = "danger"
            badge_icon = "🚨"
            summary_message = "This URL exhibits verified characteristics of a phishing attack. Do NOT visit this link or disclose any credentials."
        elif composite_score >= 25.0:
            verdict = "SUSPICIOUS"
            risk_level = "Medium Risk"
            theme_color = "warning"
            badge_icon = "⚠️"
            summary_message = "This URL exhibits suspicious markers. Exercise caution and verify identity before proceeding."
        else:
            verdict = "LEGITIMATE / SAFE"
            risk_level = "Low Risk"
            theme_color = "success"
            badge_icon = "🛡️"
            summary_message = "No significant malicious indicators or phishing patterns detected."

        return {
            "url": clean_url,
            "dissection": dissection,
            "verdict": verdict,
            "risk_level": risk_level,
            "theme_color": theme_color,
            "badge_icon": badge_icon,
            "summary_message": summary_message,
            "composite_risk_score": composite_score,
            "ml_risk_score": ml_score,
            "heuristic_risk_score": heuristic_score,
            "triggered_rules": heuristics_result["triggered_rules"],
            "rules_checked": heuristics_result["rules_checked_count"],
            "rules_triggered": heuristics_result["rules_triggered_count"],
            "features": features
        }

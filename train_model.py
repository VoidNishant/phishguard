"""
Training script for the Phishing URL Detector.
Extracts features from curated legitimate and phishing URLs,
trains a Random Forest classifier, evaluates metrics, and exports 'model.joblib'.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score

from features import extract_features, FEATURE_NAMES

# Robust curated dataset representing diverse attack vectors and legitimate web usage
DATASET_SAMPLES = [
    # --- LEGITIMATE SAMPLES (label = 0) ---
    ("https://www.google.com", 0),
    ("https://www.google.com/search?q=cybersecurity+best+practices", 0),
    ("https://www.google.co.uk", 0),
    ("https://www.google.com.au", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://en.wikipedia.org/wiki/PayPal", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://github.com/paypal/rest-api-sdk-python", 0),
    ("https://github.com/google/guava", 0),
    ("https://github.com", 0),
    ("https://docs.python.org/3/library/urllib.parse.html", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP", 0),
    ("https://www.microsoft.com/en-us/security", 0),
    ("https://www.amazon.com/dp/B08N5WRWNW", 0),
    ("https://www.amazon.co.jp", 0),
    ("https://www.apple.com/macos/sonoma", 0),
    ("https://news.ycombinator.com/item?id=38000000", 0),
    ("https://www.bbc.co.uk/news/technology", 0),
    ("https://www.bbc.com/news", 0),
    ("https://www.cnn.com/world", 0),
    ("https://www.reddit.com/r/cybersecurity", 0),
    ("https://www.reddit.com/r/google", 0),
    ("https://www.cisa.gov/resources-tools", 0),
    ("https://www.nytimes.com/section/technology", 0),
    ("https://support.google.com/accounts/answer/185839", 0),
    ("https://aws.amazon.com/products/security", 0),
    ("https://www.linkedin.com/feed", 0),
    ("https://www.netflix.com/browse", 0),
    ("https://pypi.org/project/streamlit", 0),
    ("https://kaggle.com/datasets", 0),
    ("https://store.steampowered.com/app/1091500/Cyberpunk_2077", 0),
    ("https://www.chase.com/personal/banking", 0),
    ("https://www.paypal.com/us/home", 0),
    ("https://www.paypal.co.uk", 0),
    ("https://www.bankofamerica.com", 0),
    ("https://arxiv.org/abs/2301.00001", 0),
    ("https://www.cloudflare.com/learning/access-management/what-is-zero-trust", 0),
    ("https://gitlab.com/explore", 0),
    ("https://hub.docker.com/_/python", 0),
    ("https://www.oracle.com/security", 0),
    ("https://www.ibm.com/security", 0),
    ("https://www.nationalgeographic.com", 0),
    ("https://wellsfargo.com", 0),
    ("https://www.mit.edu", 0),
    ("https://stanford.edu/research", 0),
    ("https://www.who.int/emergencies", 0),
    ("https://www.coursera.org/specializations/cyber-security", 0),
    ("https://www.udemy.com/topic/cyber-security", 0),
    ("https://slack.com/pricing", 0),
    ("https://trello.com/home", 0),
    ("https://notion.so/product", 0),
    ("https://medium.com/topic/programming", 0),
    ("https://www.quora.com", 0),
    ("https://www.khanacademy.org/computing", 0),
    ("https://www.ted.com/talks", 0),
    ("https://www.economist.com/finance-and-economics", 0),
    ("https://www.wired.com/category/security", 0),
    ("https://www.nature.com/articles", 0),
    ("https://developer.apple.com/documentation", 0),
    ("https://community.chase.com", 0),

    # --- MALICIOUS / PHISHING SAMPLES (label = 1) ---
    ("http://192.168.1.101/secure/login.php?user=target", 1),
    ("http://45.33.32.156/bank-verification/signin.html", 1),
    ("http://103.224.182.250/webscr?cmd=_login-run&dispatch=verify", 1),
    ("http://218.35.12.98/chase/account/restore", 1),
    ("http://192.168.1.55:8888/login.html", 1),
    ("http://paypal.com.account-update.xyz/login.php", 1),
    ("http://paypal-verification-center.top/confirm-identity", 1),
    ("http://secure-paypal-login.account-check.tk/auth", 1),
    ("http://apple.id.security-billing-update.club/signin", 1),
    ("http://appleid.apple.com.verify-device-support.xyz/recover", 1),
    ("http://netflix-billing-update-urgent.buzz/login", 1),
    ("http://netflix.account-issue.cf/verify", 1),
    ("http://microsoft-support-team.online-login.gq/login", 1),
    ("http://login.microsoftonline.com.attackerdomain.top/auth", 1),
    ("http://chase-bank-alert.com-security.ml/signin", 1),
    ("http://wellsfargo-security-alert-update.top/verification", 1),
    ("http://google.com@attacker-site.com/login", 1),
    ("http://paypal.com@bad-server.xyz/webscr?cmd=login", 1),
    ("http://apple.com@192.168.0.50/id/verify", 1),
    ("http://bit.ly/3xPh1shUr1", 1),
    ("http://tinyurl.com/bank-urgent-security-verify", 1),
    ("http://is.gd/chase_verification_account_locked", 1),
    ("http://cutt.ly/paypal-suspended-account", 1),
    ("http://free-giftcard-claim.stream/win", 1),
    ("http://free-crypto-giveaway.trade/binance", 1),
    ("http://verify-binance-wallet-seedphrase.buzz/connect", 1),
    ("http://metamask-wallet-auth-key.racing/restore", 1),
    ("http://compromised-site.com//redirect-paypal.com/login", 1),
    ("http://legit-news.org//evil-site.xyz/credential/stealer", 1),
    ("http://secure.account.update.login.chase.com.hackersite.xyz/verify", 1),
    ("http://online-portal.security.verification.bank.ml/auth", 1),
    ("http://bankofamerica-login-identity-confirm-update-urgent.xyz", 1),
    ("http://customer-support-amazon-prime-renewal-alert.click/renew", 1),
    ("http://facebook-security-verification-code.top/checkpoint", 1),
    ("http://instagram-copyright-infringement-appeal.buzz/submit", 1),
    ("http://whatsapp-web-qrcode-login-sync.work/auth", 1),
    ("http://twitter-blue-verification-free-claim.men/signup", 1),
    ("http://steam-community-free-skins-trade.link/tradeoffer", 1),
    ("http://dropbox-shared-document-urgent-invoice.download/view", 1),
    ("http://irs-tax-refund-status-claim.loan/refund.php", 1),
    ("http://dhl-express-package-redelivery-fee.cam/payment", 1),
    ("http://fedex-parcel-delivery-tracking-update.party/confirm", 1),
    ("http://ups-shipment-exception-pay-customs.rest/checkout", 1),
    ("http://usps-address-confirmation-redeliver.top/usps/track", 1),
    ("http://security-update-action-required-now.xyz/password/reset", 1),
    ("http://198.51.100.42/wp-content/plugins/stealer/login.php", 1),
    ("http://192.0.2.1/webmail/roundcube/login", 1),
    ("http://office365-urgent-password-expiry-notice.review/update", 1),
    ("http://coinbase-twofactor-sms-bypass.vip/verify", 1),
    ("http://ebay-resolution-center-dispute-alert.trade/login", 1),
    ("http://walmart-survey-winner-claim-reward.win/gift", 1),
    ("http://xn--pypal-4ve.com/signin", 1),
    ("http://xn--appl-43d.com/support/id", 1),
    ("http://attacker-server.com:4444/login.php", 1),
    ("http://malicious-gateway.top:9000/auth", 1),
    ("javascript:alert(document.cookie)", 1),
    ("data:text/html;base64,PHNjcmlwdD5hbGVydCgndGVzdCcpPC9zY3JpcHQ+", 1),
    ("http://chase-security-login-auth-verify.xyz", 1),
    ("http://wellsfargo-online-banking-access.top", 1),
    ("http://apple-icloud-findmy-verification.buzz", 1)
]


def train_and_export_model(model_path="model.joblib"):
    print("=== Training Phishing URL Detection Model ===")
    print(f"Total training samples: {len(DATASET_SAMPLES)}")
    
    rows = []
    labels = []

    for url, label in DATASET_SAMPLES:
        feats = extract_features(url)
        rows.append(feats)
        labels.append(label)

    df = pd.DataFrame(rows)
    X = df[FEATURE_NAMES]
    y = np.array(labels)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Train Random Forest Classifier
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        random_state=42,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)

    print(f"Test Accuracy: {acc * 100:.2f}%")
    print(f"ROC-AUC Score: {auc:.4f}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Feature Importance
    importances = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_),
        key=lambda x: x[1],
        reverse=True
    )
    print("Top Feature Importances:")
    for feat, imp in importances[:8]:
        print(f" - {feat:30s}: {imp:.4f}")

    # Export model artifact package
    package = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "accuracy": acc,
        "auc": auc,
        "importances": dict(importances)
    }
    joblib.dump(package, model_path)
    print(f"\nModel exported successfully to '{model_path}'")
    return package


if __name__ == "__main__":
    train_and_export_model()

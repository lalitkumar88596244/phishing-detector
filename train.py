"""
train.py
Trains a RandomForest classifier on features extracted from data/urls.csv
and saves the fitted model + feature order to model/phishing_model.joblib
"""

import csv
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

from features import extract_features, FEATURE_ORDER


def load_dataset(path="data/urls.csv"):
    urls, labels = [], []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))
    return urls, labels


def vectorize(urls):
    X = []
    for u in urls:
        feats = extract_features(u)
        X.append([feats[k] for k in FEATURE_ORDER])
    return np.array(X, dtype=float)


def main():
    urls, labels = load_dataset()
    X = vectorize(urls)
    y = np.array(labels)

    X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
        X, y, urls, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=10,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]

    print("=== Classification Report ===")
    print(classification_report(y_test, preds, target_names=["legit", "phishing"]))
    print("=== Confusion Matrix ===")
    print(confusion_matrix(y_test, preds))
    print(f"ROC-AUC: {roc_auc_score(y_test, probs):.4f}")

    print("\n=== Top Feature Importances ===")
    importances = sorted(
        zip(FEATURE_ORDER, clf.feature_importances_), key=lambda x: -x[1]
    )
    for name, imp in importances[:10]:
        print(f"  {name:32s} {imp:.4f}")

    joblib.dump({"model": clf, "feature_order": FEATURE_ORDER}, "model/phishing_model.joblib")
    print("\nSaved model to model/phishing_model.joblib")


if __name__ == "__main__":
    main()

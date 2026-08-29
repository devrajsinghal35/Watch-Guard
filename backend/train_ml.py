import os
from backend.ml_detector import train_model

from backend.database import Database

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, "backend", "sentry.db")
    
    # Initialize DB to ensure schemas are created
    Database(db_path)
    
    print("Starting ML model training...")
    success, results = train_model(db_path)
    
    if success:
        print("\n--- Training Results ---")
        print(f"Total events analyzed: {results['events']}")
        print(f"Selected contamination: {results['contamination']}")
        print(f"Events flagged as anomaly: {results['anomalies_flagged']} ({(results['anomalies_flagged']/results['events'])*100:.2f}%)")
        print("Model saved to: backend/sentry_model.pkl")
        print("\nNote: Because the training data has no attack labels, contamination cannot be optimized for true accuracy. We choose the value that produces a small, stable anomaly group rather than flagging a large percentage of normal history.")
    else:
        print("\nTraining aborted due to insufficient data or other errors.")

if __name__ == "__main__":
    main()

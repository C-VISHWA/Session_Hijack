# optimized_training_script.py
import pandas as pd
import pickle
import os
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score

def train_model():
    """
    Loads data, trains a complete preprocessing and classification pipeline,
    and saves it to a pickle file.
    """
    
    print("Loading data from 'realistic_session_data.csv'...")
    try:
        data = pd.read_csv('realistic_session_data.csv')
    except FileNotFoundError:
        print("Error: 'realistic_session_data.csv' not found.")
        print("Please make sure the file is in the same directory.")
        return

    print("Data loaded successfully.")

    # --- 1. Define Features and Target ---
    target = 'label'
    
    # 'status_code' is treated as categorical, not a number
    categorical_features = ['request_type', 'status_code', 'location']
    text_feature = 'user_agent'
    features = categorical_features + [text_feature]
    
    X = data[features]
    y = data[target]

    # Convert string labels to numeric (1 for hijacked, 0 for normal)
    y = y.map({'hijacked': 1, 'normal': 0})

    # --- 2. Define the Preprocessing Steps ---
    
    # Create the transformer for categorical features
    # OneHotEncoder is best for non-ordinal data like 'location'
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')
    
    # Create the transformer for the 'user_agent'
    # HashingVectorizer is fast and effective for text with
    # thousands of unique values (like user agents).
    text_transformer = HashingVectorizer(n_features=100, ngram_range=(1, 2), alternate_sign=False)

    # Bundle transformers into a ColumnTransformer
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', categorical_transformer, categorical_features),
            ('text', text_transformer, text_feature)
        ],
        remainder='drop' 
    )

    # --- 3. Create the Full Pipeline ---
    # This pipeline bundles preprocessing and the classifier.
    # This is the key to making your app work.
    model_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(random_state=42, 
                                            class_weight='balanced'))
    ])
    # Note: class_weight='balanced' helps the model pay more
    # attention to the rare 'suspicious' cases.

    # --- 4. Split Data ---
    # 'stratify=y' ensures your test set has the same
    # percentage of 'suspicious' samples as the training set.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # --- 5. Hyperparameter Tuning ---
    # This finds the best model settings for high accuracy.
    param_grid = {
        'classifier__n_estimators': [50, 100],  
        'classifier__max_depth': [10, 20],       
        'classifier__min_samples_leaf': [5, 10]    
    }
    
    # We score based on 'f1' score, which is better than
    # 'accuracy' for imbalanced anomaly data.
    print("Starting hyperparameter tuning (GridSearchCV)... This may take a minute.")
    grid_search = GridSearchCV(
        model_pipeline, 
        param_grid, 
        cv=3, 
        scoring='f1', 
        n_jobs=-1, 
        verbose=1
    )
    
    grid_search.fit(X_train, y_train)
    
    best_model = grid_search.best_estimator_
    print(f"\nBest parameters found: {grid_search.best_params_}")

    # --- 6. Evaluate the Best Model ---
    print("\n--- Model Test Results ---")
    y_pred = best_model.predict(X_test)
    
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report (shows how well it finds '1's):")
    print(classification_report(y_test, y_pred))

    # --- 7. Save the Final Pipeline ---
    model_dir = 'model'
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
        print(f"Created directory: {model_dir}")
        
    # This is the "extracting pkl file" step:
    model_path = os.path.join(model_dir, 'rf_pipeline_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(best_model, f)
        
    print(f"\n✅ Successfully trained and saved pipeline to {model_path}")

if __name__ == "__main__":
    train_model()
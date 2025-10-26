#!/usr/bin/env bash
set -o errexit # Exit on error
pip install -r requirements.txt
echo "Training the anomaly detection model..."
python optimized_training_script.py
echo "Build finished successfully!"
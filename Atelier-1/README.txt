# Run the trust agent
python3 trust_agent.py

# Collect and label data
python3 collect_dataset.py --collect --output dataset_raw.json
python3 collect_dataset.py --auto-label --input dataset_raw.json --output dataset_labeled.json

# Train calibration
python3 train_calibration.py --dataset dataset_labeled.json --method both

# Analyze results
jupyter notebook analysis.ipynb
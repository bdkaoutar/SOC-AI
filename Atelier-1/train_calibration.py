#!/usr/bin/env python3
"""
train_calibration.py - Train Calibration Parameters for Trust Agent
-------------------------------------------------------------------
This script:
1. Loads collected event-analysis pairs (ground truth dataset)
2. Trains temperature scaling or Platt scaling parameters
3. Evaluates calibration quality (Brier score, ECE)
4. Saves optimal parameters to calibration_params.json

Usage:
    python3 train_calibration.py --dataset dataset.json --method temperature
"""

import json
import numpy as np
import argparse
from scipy.optimize import minimize
from sklearn.calibration import calibration_curve
import matplotlib.pyplot as plt
from pathlib import Path


def load_dataset(filepath):
    """
    Load dataset with format:
    [
        {
            "event": {...},
            "lm_confidence": 0.85,
            "ground_truth": 1  # 1 = true positive, 0 = false positive
        },
        ...
    ]
    """
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    confidences = np.array([item['lm_confidence'] for item in data])
    labels = np.array([item['ground_truth'] for item in data])
    
    print(f"[Train] Loaded {len(data)} samples")
    print(f"[Train] True positives: {labels.sum()}, False positives: {len(labels) - labels.sum()}")
    
    return confidences, labels, data


def temperature_scaling_transform(confidences, temperature):
    """Apply temperature scaling transformation"""
    # Convert to logits
    epsilon = 1e-10
    confidences = np.clip(confidences, epsilon, 1 - epsilon)
    logits = np.log(confidences / (1 - confidences))
    
    # Scale by temperature
    scaled_logits = logits / temperature
    
    # Convert back to probabilities
    calibrated = 1 / (1 + np.exp(-scaled_logits))
    
    return calibrated


def platt_scaling_transform(confidences, a, b):
    """Apply Platt scaling transformation"""
    epsilon = 1e-10
    confidences = np.clip(confidences, epsilon, 1 - epsilon)
    logits = np.log(confidences / (1 - confidences))
    
    # Apply Platt transformation
    scaled_logits = a * logits + b
    
    # Convert back to probabilities
    calibrated = 1 / (1 + np.exp(-scaled_logits))
    
    return calibrated


def brier_score(confidences, labels):
    """Calculate Brier score (lower is better)"""
    return np.mean((confidences - labels) ** 2)


def expected_calibration_error(confidences, labels, n_bins=10):
    """
    Calculate Expected Calibration Error (ECE)
    ECE measures the difference between confidence and accuracy
    """
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    bin_lowers = bin_boundaries[:-1]
    bin_uppers = bin_boundaries[1:]
    
    ece = 0.0
    for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
        # Find samples in this bin
        in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
        prop_in_bin = np.mean(in_bin)
        
        if prop_in_bin > 0:
            accuracy_in_bin = np.mean(labels[in_bin])
            avg_confidence_in_bin = np.mean(confidences[in_bin])
            ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
    
    return ece


def optimize_temperature(confidences, labels):
    """Find optimal temperature parameter"""
    print("\n[Train] Optimizing temperature scaling...")
    
    def loss(T):
        calibrated = temperature_scaling_transform(confidences, T[0])
        return brier_score(calibrated, labels)
    
    # Search between 0.1 and 5.0
    result = minimize(loss, x0=[1.5], bounds=[(0.1, 5.0)], method='L-BFGS-B')
    
    optimal_T = result.x[0]
    print(f"[Train] Optimal temperature: {optimal_T:.3f}")
    
    return optimal_T


def optimize_platt(confidences, labels):
    """Find optimal Platt scaling parameters (a, b)"""
    print("\n[Train] Optimizing Platt scaling...")
    
    def loss(params):
        a, b = params
        calibrated = platt_scaling_transform(confidences, a, b)
        return brier_score(calibrated, labels)
    
    # Initial guess: a=1, b=0 (identity)
    result = minimize(loss, x0=[1.0, 0.0], method='L-BFGS-B')
    
    optimal_a, optimal_b = result.x
    print(f"[Train] Optimal Platt parameters: a={optimal_a:.3f}, b={optimal_b:.3f}")
    
    return optimal_a, optimal_b


def plot_calibration_curves(confidences, labels, temperature=None, platt_params=None, output_dir='results'):
    """Generate calibration curve plots"""
    Path(output_dir).mkdir(exist_ok=True)
    
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    # Plot 1: Original calibration
    fraction_of_positives, mean_predicted_value = calibration_curve(
        labels, confidences, n_bins=10, strategy='uniform'
    )
    
    axes[0].plot([0, 1], [0, 1], 'k--', label='Perfect calibration')
    axes[0].plot(mean_predicted_value, fraction_of_positives, 's-', label='Original LM')
    axes[0].set_xlabel('Mean predicted probability')
    axes[0].set_ylabel('Fraction of positives')
    axes[0].set_title('Original Calibration')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)
    
    # Plot 2: Temperature scaling
    if temperature is not None:
        calibrated_temp = temperature_scaling_transform(confidences, temperature)
        fraction_of_positives_temp, mean_predicted_value_temp = calibration_curve(
            labels, calibrated_temp, n_bins=10, strategy='uniform'
        )
        
        axes[1].plot([0, 1], [0, 1], 'k--', label='Perfect calibration')
        axes[1].plot(mean_predicted_value_temp, fraction_of_positives_temp, 's-', 
                     label=f'Temperature (T={temperature:.2f})', color='orange')
        axes[1].set_xlabel('Mean predicted probability')
        axes[1].set_ylabel('Fraction of positives')
        axes[1].set_title('Temperature Scaling')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
    
    # Plot 3: Platt scaling
    if platt_params is not None:
        a, b = platt_params
        calibrated_platt = platt_scaling_transform(confidences, a, b)
        fraction_of_positives_platt, mean_predicted_value_platt = calibration_curve(
            labels, calibrated_platt, n_bins=10, strategy='uniform'
        )
        
        axes[2].plot([0, 1], [0, 1], 'k--', label='Perfect calibration')
        axes[2].plot(mean_predicted_value_platt, fraction_of_positives_platt, 's-',
                     label=f'Platt (a={a:.2f}, b={b:.2f})', color='green')
        axes[2].set_xlabel('Mean predicted probability')
        axes[2].set_ylabel('Fraction of positives')
        axes[2].set_title('Platt Scaling')
        axes[2].legend()
        axes[2].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/calibration_curves.png', dpi=300, bbox_inches='tight')
    print(f"[Train] Saved calibration curves to {output_dir}/calibration_curves.png")
    plt.close()


def plot_confidence_distribution(confidences, labels, temperature=None, platt_params=None, output_dir='results'):
    """Plot confidence distribution before/after calibration"""
    Path(output_dir).mkdir(exist_ok=True)
    
    fig, axes = plt.subplots(1, 3, figsize=(15, 4))
    
    # Original
    axes[0].hist(confidences[labels == 1], bins=20, alpha=0.7, label='True Positives', color='green')
    axes[0].hist(confidences[labels == 0], bins=20, alpha=0.7, label='False Positives', color='red')
    axes[0].set_xlabel('Confidence')
    axes[0].set_ylabel('Count')
    axes[0].set_title('Original LM Confidence')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)
    
    # Temperature
    if temperature is not None:
        calibrated_temp = temperature_scaling_transform(confidences, temperature)
        axes[1].hist(calibrated_temp[labels == 1], bins=20, alpha=0.7, label='True Positives', color='green')
        axes[1].hist(calibrated_temp[labels == 0], bins=20, alpha=0.7, label='False Positives', color='red')
        axes[1].set_xlabel('Confidence')
        axes[1].set_ylabel('Count')
        axes[1].set_title(f'Temperature Scaling (T={temperature:.2f})')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
    
    # Platt
    if platt_params is not None:
        a, b = platt_params
        calibrated_platt = platt_scaling_transform(confidences, a, b)
        axes[2].hist(calibrated_platt[labels == 1], bins=20, alpha=0.7, label='True Positives', color='green')
        axes[2].hist(calibrated_platt[labels == 0], bins=20, alpha=0.7, label='False Positives', color='red')
        axes[2].set_xlabel('Confidence')
        axes[2].set_ylabel('Count')
        axes[2].set_title(f'Platt Scaling (a={a:.2f}, b={b:.2f})')
        axes[2].legend()
        axes[2].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/confidence_distributions.png', dpi=300, bbox_inches='tight')
    print(f"[Train] Saved confidence distributions to {output_dir}/confidence_distributions.png")
    plt.close()


def evaluate_and_compare(confidences, labels, temperature, platt_params, output_dir='results'):
    """Evaluate all methods and generate comparison table"""
    Path(output_dir).mkdir(exist_ok=True)
    
    # Original
    brier_original = brier_score(confidences, labels)
    ece_original = expected_calibration_error(confidences, labels)
    
    # Temperature
    calibrated_temp = temperature_scaling_transform(confidences, temperature)
    brier_temp = brier_score(calibrated_temp, labels)
    ece_temp = expected_calibration_error(calibrated_temp, labels)
    
    # Platt
    a, b = platt_params
    calibrated_platt = platt_scaling_transform(confidences, a, b)
    brier_platt = brier_score(calibrated_platt, labels)
    ece_platt = expected_calibration_error(calibrated_platt, labels)
    
    # Print results
    print("\n" + "="*80)
    print("CALIBRATION EVALUATION RESULTS")
    print("="*80)
    print(f"{'Method':<20} {'Brier Score':<15} {'ECE':<15} {'Improvement':<15}")
    print("-"*80)
    print(f"{'Original LM':<20} {brier_original:.4f}{'':<10} {ece_original:.4f}{'':<10} {'—':<15}")
    print(f"{'Temperature':<20} {brier_temp:.4f}{'':<10} {ece_temp:.4f}{'':<10} {((brier_original - brier_temp)/brier_original*100):+.1f}%")
    print(f"{'Platt':<20} {brier_platt:.4f}{'':<10} {ece_platt:.4f}{'':<10} {((brier_original - brier_platt)/brier_original*100):+.1f}%")
    print("="*80 + "\n")
    
    # Save results
    results = {
        'original': {'brier': float(brier_original), 'ece': float(ece_original)},
        'temperature': {'brier': float(brier_temp), 'ece': float(ece_temp), 'T': float(temperature)},
        'platt': {'brier': float(brier_platt), 'ece': float(ece_platt), 'a': float(a), 'b': float(b)}
    }
    
    with open(f'{output_dir}/evaluation_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[Train] Saved evaluation results to {output_dir}/evaluation_results.json")
    
    return results


def save_calibration_params(method, temperature=None, platt_params=None, output_file='calibration_params.json'):
    """Save optimal parameters for production use"""
    params = {'method': method}
    
    if method == 'temperature':
        params['temperature'] = float(temperature)
        params['platt_a'] = 1.0
        params['platt_b'] = 0.0
    elif method == 'platt':
        params['temperature'] = 1.0
        a, b = platt_params
        params['platt_a'] = float(a)
        params['platt_b'] = float(b)
    
    with open(output_file, 'w') as f:
        json.dump(params, f, indent=2)
    
    print(f"\n[Train] ✅ Saved calibration parameters to {output_file}")
    print(f"[Train] Parameters: {params}")


def main():
    parser = argparse.ArgumentParser(description='Train calibration parameters for Trust Agent')
    parser.add_argument('--dataset', type=str, required=True, help='Path to labeled dataset JSON')
    parser.add_argument('--method', type=str, choices=['temperature', 'platt', 'both'], default='both',
                        help='Calibration method to use')
    parser.add_argument('--output-dir', type=str, default='results', help='Output directory for plots and results')
    
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("TRUST AGENT CALIBRATION TRAINING")
    print("="*80)
    print(f"Dataset: {args.dataset}")
    print(f"Method: {args.method}")
    print(f"Output: {args.output_dir}")
    print("="*80 + "\n")
    
    # Load dataset
    confidences, labels, data = load_dataset(args.dataset)
    
    # Train calibration methods
    temperature = None
    platt_params = None
    
    if args.method in ['temperature', 'both']:
        temperature = optimize_temperature(confidences, labels)
    
    if args.method in ['platt', 'both']:
        platt_params = optimize_platt(confidences, labels)
    
    # Generate plots
    plot_calibration_curves(confidences, labels, temperature, platt_params, args.output_dir)
    plot_confidence_distribution(confidences, labels, temperature, platt_params, args.output_dir)
    
    # Evaluate and compare
    if args.method == 'both':
        results = evaluate_and_compare(confidences, labels, temperature, platt_params, args.output_dir)
        
        # Choose best method based on Brier score
        if results['temperature']['brier'] < results['platt']['brier']:
            print("\n[Train] 🏆 Temperature scaling performs better!")
            save_calibration_params('temperature', temperature=temperature)
        else:
            print("\n[Train] 🏆 Platt scaling performs better!")
            save_calibration_params('platt', platt_params=platt_params)
    
    elif args.method == 'temperature':
        save_calibration_params('temperature', temperature=temperature)
    
    elif args.method == 'platt':
        save_calibration_params('platt', platt_params=platt_params)
    
    print("\n[Train] ✅ Training complete!")


if __name__ == "__main__":
    main()

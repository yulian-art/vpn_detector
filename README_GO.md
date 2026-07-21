# VPN Detector Go Build

This directory is now also a runnable Go project.

The original Python files, configs, tests, and data-compatible formats are kept in place. The Go build adds native Phase 1 pipeline support without deleting or moving existing project data.

## Run

```powershell
cd vpn_detector
go test ./...
go run . --help
```

Example Phase 1 flow:

```powershell
go run . labels-build --input ../data/pcaps --vpn-root ../data/pcaps/vpn --nonvpn-root ../data/pcaps/nonvpn --out-parquet results/labels_master.csv --review-xlsx results/labels_review.csv
go run . extract --input ../data/pcaps --out results/features.jsonl --timeout 300 --max-flows 80
go run . detect --features results/features.jsonl --out results/rule_results.jsonl --excel results/rule_results.csv
go run . build-dataset --features results/features.jsonl --labels results/labels_master.csv --out datasets/dataset.csv
go run . train-ml --dataset datasets/dataset.csv --target binary --feature-set all --model logreg --out-dir models
go run . predict-ml --model models/binary_all_logreg.joblib --dataset datasets/dataset.csv --out results/ml_predictions.csv
go run . fuse --rule-results results/rule_results.jsonl --ml-predictions results/ml_predictions.csv --out results/fusion_predictions.csv
```

## Compatibility Notes

- `extract`, `extract-flow`, and `extract-seq` require `tshark` from Wireshark.
- The Go build uses standard-library CSV/JSONL output. If a `.parquet` or `.xlsx` suffix is supplied, the command still writes CSV-formatted table data to keep the pipeline runnable.
- `train-ml` writes a Go JSON model. The filename can still be `.joblib` for CLI compatibility, but it is not a Python joblib artifact.
- Heavy Python-only commands such as DL training, anonymization, and label audit remain available in the preserved Python project.

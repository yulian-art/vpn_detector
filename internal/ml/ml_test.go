package ml

import (
	"os"
	"path/filepath"
	"testing"

	"vpn_detector/internal/core"
)

func TestTrainPredictBinaryModel(t *testing.T) {
	dir := t.TempDir()
	ds := filepath.Join(dir, "dataset.csv")
	rows := []map[string]any{
		{"sample_id": "s0", "file_name": "n0.pcapng", "label_binary": 0, "label_confidence": "strong", "sample_weight": 1, "pkt_total_packets": 10, "block_1300_ratio": 0.01},
		{"sample_id": "s1", "file_name": "n1.pcapng", "label_binary": 0, "label_confidence": "strong", "sample_weight": 1, "pkt_total_packets": 12, "block_1300_ratio": 0.02},
		{"sample_id": "s2", "file_name": "v0.pcapng", "label_binary": 1, "label_confidence": "strong", "sample_weight": 1, "pkt_total_packets": 80, "block_1300_ratio": 0.55},
		{"sample_id": "s3", "file_name": "v1.pcapng", "label_binary": 1, "label_confidence": "strong", "sample_weight": 1, "pkt_total_packets": 90, "block_1300_ratio": 0.60},
	}
	if err := core.WriteCSV(ds, rows, []string{"sample_id", "file_name", "label_binary", "label_confidence", "sample_weight", "pkt_total_packets", "block_1300_ratio"}); err != nil {
		t.Fatal(err)
	}
	modelPath, err := Train(ds, "binary", "all", "logreg", filepath.Join(dir, "models"), 0.25, 42)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(modelPath); err != nil {
		t.Fatal(err)
	}
	predPath := filepath.Join(dir, "pred.csv")
	preds, err := Predict(modelPath, ds, "", predPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(preds) != len(rows) {
		t.Fatalf("preds=%d, want %d", len(preds), len(rows))
	}
	if _, err := os.Stat(predPath); err != nil {
		t.Fatal(err)
	}
}

package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"vpn_detector/internal/core"
	"vpn_detector/internal/dataset"
)

type Model struct {
	Kind         string    `json:"kind"`
	Target       string    `json:"target"`
	FeatureSet   string    `json:"feature_set"`
	Columns      []string  `json:"columns"`
	Means        []float64 `json:"means"`
	Stds         []float64 `json:"stds"`
	Weights      []float64 `json:"weights"`
	Bias         float64   `json:"bias"`
	Threshold    float64   `json:"threshold"`
	ConstantProb *float64  `json:"constant_prob,omitempty"`
}

func Train(datasetPath, target, featureSet, modelName, outDir string, testSize float64, randomState int) (string, error) {
	if target != "binary" {
		return "", fmt.Errorf("Go ML currently supports binary target only")
	}
	rows, err := dataset.LoadDatasetRows(datasetPath)
	if err != nil {
		return "", err
	}
	cols := dataset.FeatureColumns(rows, featureSet)
	if len(cols) == 0 {
		return "", fmt.Errorf("no numeric feature columns for feature-set %s", featureSet)
	}
	trainRows := []map[string]any{}
	labels := []float64{}
	weights := []float64{}
	for _, row := range rows {
		label, ok := normalizeBinary(row["label_binary"])
		if !ok {
			continue
		}
		weight := core.SafeFloat(row["sample_weight"])
		if weight <= 0 {
			weight = 1
		}
		trainRows = append(trainRows, row)
		labels = append(labels, float64(label))
		weights = append(weights, weight)
	}
	if len(trainRows) == 0 {
		return "", fmt.Errorf("no labeled rows found")
	}
	positive := 0
	for _, y := range labels {
		if y == 1 {
			positive++
		}
	}
	if positive == 0 || positive == len(labels) {
		prob := float64(positive) / float64(len(labels))
		m := Model{Kind: "constant", Target: target, FeatureSet: featureSet, Columns: cols, Threshold: 0.5, ConstantProb: &prob}
		return saveModel(m, outDir, target, featureSet, modelName)
	}

	means, stds := fitScaler(trainRows, cols)
	weightsModel := make([]float64, len(cols))
	bias := 0.0
	lr := 0.15
	epochs := 900
	for epoch := 0; epoch < epochs; epoch++ {
		gradW := make([]float64, len(cols))
		gradB := 0.0
		totalWeight := 0.0
		for i, row := range trainRows {
			x := scaledValues(row, cols, means, stds)
			p := sigmoid(dot(weightsModel, x) + bias)
			errTerm := (p - labels[i]) * weights[i]
			for j := range gradW {
				gradW[j] += errTerm * x[j]
			}
			gradB += errTerm
			totalWeight += weights[i]
		}
		if totalWeight == 0 {
			totalWeight = float64(len(trainRows))
		}
		for j := range weightsModel {
			weightsModel[j] -= lr * gradW[j] / totalWeight
		}
		bias -= lr * gradB / totalWeight
		lr *= 0.997
	}
	m := Model{Kind: "logreg", Target: target, FeatureSet: featureSet, Columns: cols, Means: means, Stds: stds, Weights: weightsModel, Bias: bias, Threshold: 0.5}
	return saveModel(m, outDir, target, featureSet, modelName)
}

func Predict(modelPath, datasetPath, featuresPath, outPath string) ([]map[string]any, error) {
	model, err := LoadModel(modelPath)
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	if datasetPath != "" {
		rows, err = dataset.LoadDatasetRows(datasetPath)
		if err != nil {
			return nil, err
		}
	} else if featuresPath != "" {
		features, err := core.LoadFeatureFile(featuresPath)
		if err != nil {
			return nil, err
		}
		for _, rec := range features {
			rows = append(rows, dataset.FlattenFeatureRecord(rec))
		}
	} else {
		return nil, fmt.Errorf("dataset or features input is required")
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		prob := model.Prob(row)
		label := 0
		if prob >= model.Threshold {
			label = 1
		}
		out = append(out, map[string]any{
			"sample_id":        row["sample_id"],
			"source_archive":   row["source_archive"],
			"pcap_member":      row["pcap_member"],
			"file_name":        row["file_name"],
			"ml_pred_label":    label,
			"ml_prob_vpn":      round(prob, 6),
			"ml_pred_prob_max": round(math.Max(prob, 1-prob), 6),
			"model_path":       modelPath,
		})
	}
	preferred := []string{"sample_id", "source_archive", "pcap_member", "file_name", "ml_pred_label", "ml_prob_vpn", "ml_pred_prob_max", "model_path"}
	return out, core.WriteCSV(outPath, out, preferred)
}

func LoadModel(path string) (Model, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Model{}, err
	}
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return Model{}, fmt.Errorf("model is not a Go JSON model: %w", err)
	}
	if m.Threshold == 0 {
		m.Threshold = 0.5
	}
	return m, nil
}

func (m Model) Prob(row map[string]any) float64 {
	if m.ConstantProb != nil {
		return clamp(*m.ConstantProb)
	}
	x := scaledValues(row, m.Columns, m.Means, m.Stds)
	return clamp(sigmoid(dot(m.Weights, x) + m.Bias))
}

func saveModel(m Model, outDir, target, featureSet, modelName string) (string, error) {
	if outDir == "" {
		outDir = "models"
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(outDir, fmt.Sprintf("%s_%s_%s.joblib", target, featureSet, modelName))
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0644)
}

func fitScaler(rows []map[string]any, cols []string) ([]float64, []float64) {
	means := make([]float64, len(cols))
	stds := make([]float64, len(cols))
	for j, col := range cols {
		for _, row := range rows {
			means[j] += core.SafeFloat(row[col])
		}
		means[j] /= float64(len(rows))
	}
	for j, col := range cols {
		for _, row := range rows {
			d := core.SafeFloat(row[col]) - means[j]
			stds[j] += d * d
		}
		stds[j] = math.Sqrt(stds[j] / float64(len(rows)))
		if stds[j] == 0 || math.IsNaN(stds[j]) || math.IsInf(stds[j], 0) {
			stds[j] = 1
		}
	}
	return means, stds
}

func scaledValues(row map[string]any, cols []string, means []float64, stds []float64) []float64 {
	x := make([]float64, len(cols))
	for i, col := range cols {
		mean, std := 0.0, 1.0
		if i < len(means) {
			mean = means[i]
		}
		if i < len(stds) && stds[i] != 0 {
			std = stds[i]
		}
		x[i] = (core.SafeFloat(row[col]) - mean) / std
	}
	return x
}

func normalizeBinary(value any) (int, bool) {
	s := strings.ToLower(strings.TrimSpace(core.ToString(value)))
	switch s {
	case "1", "1.0", "true", "vpn", "yes", "y", "positive":
		return 1, true
	case "0", "0.0", "false", "nonvpn", "non-vpn", "normal", "no", "n", "negative":
		return 0, true
	default:
		return 0, false
	}
}

func sigmoid(x float64) float64 {
	if x >= 0 {
		z := math.Exp(-x)
		return 1 / (1 + z)
	}
	z := math.Exp(x)
	return z / (1 + z)
}

func dot(w []float64, x []float64) float64 {
	n := len(w)
	if len(x) < n {
		n = len(x)
	}
	total := 0.0
	for i := 0; i < n; i++ {
		total += w[i] * x[i]
	}
	return total
}

func clamp(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0.5
	}
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func round(v float64, digits int) float64 {
	pow := 1.0
	for i := 0; i < digits; i++ {
		pow *= 10
	}
	return math.Round(v*pow) / pow
}

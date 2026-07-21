package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vpn_detector/internal/core"
	"vpn_detector/internal/dataset"
	"vpn_detector/internal/extract"
	"vpn_detector/internal/fusion"
	"vpn_detector/internal/labels"
	"vpn_detector/internal/ml"
)

func Run(args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		PrintHelp()
		return nil
	}
	cmd := args[0]
	rest := args[1:]
	switch cmd {
	case "full":
		return cmdFull(rest)
	case "extract":
		return cmdExtract(rest)
	case "extract-flow":
		return cmdExtractFlow(rest)
	case "extract-seq":
		return cmdExtractSeq(rest)
	case "detect":
		return cmdDetect(rest)
	case "labels", "labels-build":
		return cmdLabels(cmd, rest)
	case "build-dataset":
		return cmdBuildDataset(rest)
	case "train", "train-ml":
		return cmdTrain(rest)
	case "predict", "predict-ml":
		return cmdPredict(rest)
	case "fuse":
		return cmdFuse(rest)
	case "build-seq-dataset", "train-dl", "predict-dl", "audit-labels", "labels-audit", "anonymize":
		return fmt.Errorf("%s is not implemented in the pure Go build; the original Python files are preserved for this command", cmd)
	default:
		return fmt.Errorf("unknown command %q; run --help", cmd)
	}
}

func PrintHelp() {
	fmt.Println(`VPN Detector Go

Usage:
  go run . <command> [options]

Commands:
  full             extract + rule detection
  extract          extract pcap features to JSONL using tshark
  extract-flow     export flow-level CSV features using tshark
  extract-seq      export first-N packet sequence CSV features using tshark
  detect           rule detection from features.jsonl
  labels           build safer label manifest
  labels-build     build strict labels master and review table
  build-dataset    flatten features + labels into ML-ready CSV
  train-ml         train lightweight binary logistic model
  predict-ml       predict with a Go JSON model
  fuse             fuse rule and ML predictions

Notes:
  Parquet/XLSX suffixes are accepted, but this Go build writes CSV-formatted tables.
  Existing Python source and data files are left in place.`)
}

func cmdFull(args []string) error {
	fs := newFlagSet("full")
	input := fs.String("input", "", "input pcap/dir/zip, comma-separated for multiple")
	outDir := fs.String("out-dir", "results", "output directory")
	features := fs.String("features", "", "features JSONL path")
	results := fs.String("results", "", "rule results JSONL path")
	excel := fs.String("excel", "", "CSV/XLSX-compatible summary path")
	timeout := fs.Int("timeout", 180, "tshark timeout seconds")
	maxFlows := fs.Int("max-flows", 50, "top flows per file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inputs := splitInputs(*input, fs.Args())
	if len(inputs) == 0 {
		return fmt.Errorf("--input is required")
	}
	if *features == "" {
		*features = filepath.Join(*outDir, "features.jsonl")
	}
	if *results == "" {
		*results = filepath.Join(*outDir, "results.jsonl")
	}
	if *excel == "" {
		*excel = filepath.Join(*outDir, "results.csv")
	}
	if err := extract.ExtractFeatures(inputs, *features, *timeout, *maxFlows); err != nil {
		return err
	}
	_, err := core.RunDetection(*features, *results, *excel)
	return err
}

func cmdExtract(args []string) error {
	fs := newFlagSet("extract")
	input := fs.String("input", "", "input pcap/dir/zip")
	out := fs.String("out", "features.jsonl", "output JSONL")
	timeout := fs.Int("timeout", 180, "tshark timeout seconds")
	maxFlows := fs.Int("max-flows", 50, "top flows per file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inputs := splitInputs(*input, fs.Args())
	if len(inputs) == 0 {
		return fmt.Errorf("--input is required")
	}
	return extract.ExtractFeatures(inputs, *out, *timeout, *maxFlows)
}

func cmdExtractFlow(args []string) error {
	fs := newFlagSet("extract-flow")
	input := fs.String("input", "", "input pcap/dir/zip")
	out := fs.String("out", "results/flow_features.csv", "output table")
	timeout := fs.Int("timeout", 300, "tshark timeout seconds")
	directionMode := fs.String("direction-mode", "first_packet", "first_packet or canonical")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inputs := splitInputs(*input, fs.Args())
	if len(inputs) == 0 {
		return fmt.Errorf("--input is required")
	}
	return extract.ExtractFlowFeatures(inputs, *out, *timeout, *directionMode)
}

func cmdExtractSeq(args []string) error {
	fs := newFlagSet("extract-seq")
	input := fs.String("input", "", "input pcap/dir/zip")
	out := fs.String("out", "results/sequence_first64.csv", "output table")
	firstN := fs.Int("first-n", 64, "32 or 64")
	timeout := fs.Int("timeout", 300, "tshark timeout seconds")
	directionMode := fs.String("direction-mode", "first_packet", "first_packet or canonical")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inputs := splitInputs(*input, fs.Args())
	if len(inputs) == 0 {
		return fmt.Errorf("--input is required")
	}
	return extract.ExtractSequenceFeatures(inputs, *out, *firstN, *timeout, *directionMode)
}

func cmdDetect(args []string) error {
	fs := newFlagSet("detect")
	features := fs.String("features", "", "features JSONL")
	out := fs.String("out", "results.jsonl", "output JSONL")
	excel := fs.String("excel", "results.csv", "summary CSV path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *features == "" {
		return fmt.Errorf("--features is required")
	}
	_, err := core.RunDetection(*features, *out, *excel)
	return err
}

func cmdLabels(command string, args []string) error {
	fs := newFlagSet(command)
	input := fs.String("input", "", "input pcap/dir/zip/table")
	out := fs.String("out", "manifest_v4.csv", "output manifest for labels command")
	outParquet := fs.String("out-parquet", "labels_master.csv", "labels master path")
	review := fs.String("review-xlsx", "labels_review.csv", "review table path")
	vpnRoot := fs.String("vpn-root", "", "known VPN root")
	nonVPNRoot := fs.String("nonvpn-root", "", "known NonVPN root")
	manual := fs.String("manual-review", "", "side vote table")
	analysis := fs.String("analysis-docs", "", "side vote table")
	rules := fs.String("rule-results", "", "side vote table")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inputs := splitInputs(*input, fs.Args())
	if len(inputs) == 0 {
		return fmt.Errorf("--input is required")
	}
	if command == "labels" {
		return labels.BuildManifest(inputs, *out, *vpnRoot, *nonVPNRoot)
	}
	side := []string{}
	side = append(side, splitList(*manual)...)
	side = append(side, splitList(*analysis)...)
	side = append(side, splitList(*rules)...)
	_, err := labels.BuildLabelsMaster(inputs, *outParquet, *review, *vpnRoot, *nonVPNRoot, side)
	return err
}

func cmdBuildDataset(args []string) error {
	fs := newFlagSet("build-dataset")
	features := fs.String("features", "", "features JSONL")
	labelsPath := fs.String("labels", "", "labels table")
	out := fs.String("out", "datasets/ml_dataset.csv", "output dataset")
	csvOut := fs.String("csv-out", "", "optional CSV copy")
	includeUnlabeled := fs.Bool("include-unlabeled", false, "keep unlabeled rows")
	featureVersion := fs.String("feature-version", "v2_flatten_go", "feature version")
	labelVersion := fs.String("label-version", "labels_master_go", "label version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *features == "" {
		return fmt.Errorf("--features is required")
	}
	_, err := dataset.BuildDataset(*features, *labelsPath, *out, *csvOut, *includeUnlabeled, *featureVersion, *labelVersion)
	return err
}

func cmdTrain(args []string) error {
	fs := newFlagSet("train-ml")
	ds := fs.String("dataset", "", "dataset CSV")
	target := fs.String("target", "binary", "binary")
	featureSet := fs.String("feature-set", "all", "all/no_identity/behavior_only/tls_only/dns_only/port_only")
	modelName := fs.String("model", "logreg", "model name stored in output filename")
	outDir := fs.String("out-dir", "models", "model output directory")
	testSize := fs.Float64("test-size", 0.25, "accepted for CLI compatibility")
	randomState := fs.Int("random-state", 42, "accepted for CLI compatibility")
	ablation := fs.Bool("ablation", false, "accepted for CLI compatibility")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = ablation
	if *ds == "" {
		return fmt.Errorf("--dataset is required")
	}
	path, err := ml.Train(*ds, *target, *featureSet, *modelName, *outDir, *testSize, *randomState)
	if err == nil {
		fmt.Fprintln(os.Stdout, "wrote model:", path)
	}
	return err
}

func cmdPredict(args []string) error {
	fs := newFlagSet("predict-ml")
	modelPath := fs.String("model", "", "Go JSON model path")
	ds := fs.String("dataset", "", "dataset CSV")
	features := fs.String("features", "", "features JSONL")
	out := fs.String("out", "ml_predictions.csv", "output predictions CSV")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *modelPath == "" {
		return fmt.Errorf("--model is required")
	}
	if *ds == "" && *features == "" {
		return fmt.Errorf("--dataset or --features is required")
	}
	_, err := ml.Predict(*modelPath, *ds, *features, *out)
	return err
}

func cmdFuse(args []string) error {
	fs := newFlagSet("fuse")
	rules := fs.String("rule-results", "", "rule results JSONL")
	preds := fs.String("ml-predictions", "", "ML predictions CSV")
	out := fs.String("out", "fusion_predictions.csv", "fusion output table")
	csvOut := fs.String("csv-out", "", "optional CSV copy")
	dlPreds := fs.String("dl-predictions", "", "optional DL predictions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rules == "" || *preds == "" {
		return fmt.Errorf("--rule-results and --ml-predictions are required")
	}
	_, err := fusion.FuseDecisions(*rules, *preds, *out, *csvOut, *dlPreds)
	return err
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	return fs
}

func splitInputs(primary string, extras []string) []string {
	out := splitList(primary)
	for _, extra := range extras {
		if strings.HasPrefix(extra, "-") {
			continue
		}
		out = append(out, splitList(extra)...)
	}
	return out
}

func splitList(s string) []string {
	out := []string{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

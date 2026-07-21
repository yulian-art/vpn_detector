package fusion

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vpn_detector/internal/core"
)

func TestHighConfidenceRuleOverridesMLNegative(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rules.jsonl")
	rule := map[string]any{
		"sample_id":     "s1",
		"file_name":     "a.pcapng",
		"verdict":       "vpn_confirmed",
		"confidence":    92,
		"matched_rules": []string{"R_HIGH"},
		"evidence":      []string{"strong rule evidence"},
	}
	writeJSONL(t, rulePath, rule)
	predPath := filepath.Join(dir, "pred.csv")
	if err := core.WriteCSV(predPath, []map[string]any{{"sample_id": "s1", "file_name": "a.pcapng", "ml_pred_label": "0", "ml_prob_vpn": 0.05}}, []string{"sample_id", "file_name", "ml_pred_label", "ml_prob_vpn"}); err != nil {
		t.Fatal(err)
	}
	rows, err := FuseDecisions(rulePath, predPath, filepath.Join(dir, "fusion.csv"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if rows[0]["final_verdict"] != "vpn_confirmed" {
		t.Fatalf("final_verdict=%v", rows[0]["final_verdict"])
	}
	if rows[0]["decision_reason_code"] != "high_conf_rule_override" {
		t.Fatalf("reason=%v", rows[0]["decision_reason_code"])
	}
}

func TestFusionFullOuterKeepsMLOnlyAndRuleOnly(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rules.jsonl")
	writeJSONL(t, rulePath, map[string]any{
		"sample_id":     "rule-only",
		"file_name":     "rule_only.pcapng",
		"verdict":       "vpn_confirmed",
		"confidence":    95,
		"matched_rules": []string{"R_HIGH"},
		"evidence":      []string{"strong rule evidence"},
	})
	predPath := filepath.Join(dir, "pred.csv")
	if err := core.WriteCSV(predPath, []map[string]any{
		{"sample_id": "rule-only", "file_name": "rule_only.pcapng", "ml_pred_label": "0", "ml_prob_vpn": 0.1},
		{"sample_id": "ml-only", "file_name": "ml_only.pcapng", "ml_pred_label": "1", "ml_prob_vpn": 0.91},
	}, []string{"sample_id", "file_name", "ml_pred_label", "ml_prob_vpn"}); err != nil {
		t.Fatal(err)
	}
	rows, err := FuseDecisions(rulePath, predPath, filepath.Join(dir, "fusion.csv"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d, want 2", len(rows))
	}
	bySample := map[string]map[string]any{}
	for _, row := range rows {
		bySample[row["sample_id"].(string)] = row
	}
	if bySample["rule-only"]["final_verdict"] != "vpn_confirmed" {
		t.Fatalf("rule-only=%v", bySample["rule-only"]["final_verdict"])
	}
	if bySample["ml-only"]["final_verdict"] != "vpn_suspected" {
		t.Fatalf("ml-only=%v", bySample["ml-only"]["final_verdict"])
	}
	if bySample["ml-only"]["decision_reason_code"] != "ml_high_rule_missing" {
		t.Fatalf("reason=%v", bySample["ml-only"]["decision_reason_code"])
	}
}

func writeJSONL(t *testing.T, path string, row map[string]any) {
	t.Helper()
	data, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

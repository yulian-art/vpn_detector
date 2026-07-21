package fusion

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"vpn_detector/internal/core"
)

func ReadPredictions(path string) ([]map[string]any, error) {
	rows, err := core.ReadTable(path)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, row := range rows {
		m := map[string]any{}
		for k, v := range row {
			if isNumber(v) {
				m[k] = core.SafeFloat(v)
			} else {
				m[k] = v
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func MLProbVPN(row map[string]any) float64 {
	for _, col := range []string{"ml_prob_vpn", "ml_prob_1", "ml_prob_true", "ml_prob_VPN"} {
		if _, ok := row[col]; ok {
			return core.SafeFloat(row[col])
		}
	}
	label := strings.ToLower(core.ToString(row["ml_pred_label"]))
	if label == "1" || label == "vpn" || label == "true" {
		p := core.SafeFloat(row["ml_pred_prob_max"])
		if p == 0 {
			return 0.5
		}
		return p
	}
	if _, ok := row["ml_pred_prob_max"]; ok {
		return 1.0 - core.SafeFloat(row["ml_pred_prob_max"])
	}
	return 0
}

func FuseOne(rule map[string]any, ml map[string]any, dl map[string]any, includeDL bool) map[string]any {
	hasRule := len(rule) > 0
	hasML := len(ml) > 0
	ruleVerdict := core.ToString(firstAny(rule["verdict"], rule["rule_verdict"], "missing_rule_result"))
	ruleConf := core.SafeFloat(firstAny(rule["confidence"], rule["rule_confidence"]))
	prob := 0.0
	if hasML {
		prob = MLProbVPN(ml)
	}
	mlLabel := ""
	if hasML {
		mlLabel = core.ToString(ml["ml_pred_label"])
	}
	hasDL := includeDL && len(dl) > 0
	dlProb := core.SafeFloat(dl["dl_prob_vpn"])

	final := "no_vpn_evidence"
	finalConf := 0.0
	reason := "no_strong_signal"
	review := false
	switch {
	case ruleVerdict == "vpn_confirmed" && ruleConf >= 85:
		final = "vpn_confirmed"
		finalConf = math.Max(ruleConf/100.0, 0.85)
		reason = "high_conf_rule_override"
	case hasDL && dlProb >= 0.85 && ruleVerdict != "vpn_confirmed" && ruleVerdict != "vpn_suspected" && prob < 0.55:
		final = "vpn_suspected"
		finalConf = dlProb
		reason = "dl_high_rule_ml_low"
		review = true
	case !hasRule && prob >= 0.85:
		final = "vpn_suspected"
		finalConf = prob
		reason = "ml_high_rule_missing"
		review = true
	case (ruleVerdict == "vpn_confirmed" || ruleVerdict == "vpn_suspected") && prob >= 0.55:
		if prob >= 0.8 || ruleConf >= 85 {
			final = "vpn_confirmed"
		} else {
			final = "vpn_suspected"
		}
		finalConf = math.Max(ruleConf/100.0, prob)
		reason = "rule_ml_agree"
	case prob >= 0.85:
		final = "vpn_suspected"
		finalConf = prob
		reason = "ml_high_rule_not_confirmed"
		review = true
	case ruleVerdict == "weak_suspicious" || prob >= 0.55:
		final = "weak_suspicious"
		finalConf = math.Max(ruleConf/100.0, prob)
		reason = "weak_rule_or_ml_signal"
		review = true
	default:
		final = "no_vpn_evidence"
		if prob > 0 {
			finalConf = math.Max(ruleConf/100.0, 1.0-prob)
		} else {
			finalConf = ruleConf / 100.0
		}
		reason = "no_strong_signal"
	}

	result := map[string]any{
		"sample_id":            firstAny(ml["sample_id"], rule["sample_id"], dl["sample_id"]),
		"source_archive":       firstAny(rule["source_archive"], ml["source_archive"], dl["source_archive"]),
		"pcap_member":          firstAny(rule["pcap_member"], ml["pcap_member"], dl["pcap_member"]),
		"file_name":            firstAny(rule["file_name"], ml["file_name"], dl["file_name"]),
		"final_verdict":        final,
		"final_confidence":     round(finalConf, 4),
		"rule_verdict":         ruleVerdict,
		"rule_confidence":      ruleConf,
		"ml_prob_vpn":          round(prob, 6),
		"ml_pred_label":        mlLabel,
		"matched_rules":        jsonString(rule["matched_rules"]),
		"evidence":             jsonString(rule["evidence"]),
		"top_sni":              jsonString(rule["top_sni"]),
		"top_dns":              jsonString(rule["top_dns"]),
		"best_block":           rule["best_block"],
		"best_block_ratio":     rule["best_block_ratio"],
		"decision_reason_code": reason,
		"review_recommended":   review,
	}
	if includeDL {
		result["dl_pred_label"] = int(core.SafeFloat(firstAny(dl["dl_pred_label"], boolToInt(dlProb >= 0.5))))
		result["dl_prob_vpn"] = round(dlProb, 6)
		result["dl_evidence_count"] = int(core.SafeFloat(dl["dl_evidence_count"]))
		result["dl_top_k_mean_prob_vpn"] = round(core.SafeFloat(firstAny(dl["dl_top_k_mean_prob_vpn"], dlProb)), 6)
		result["dl_high_risk_flow_count"] = int(core.SafeFloat(dl["dl_high_risk_flow_count"]))
	}
	return result
}

func FuseDecisions(ruleResults, mlPredictions, outPath, csvOut, dlPredictions string) ([]map[string]any, error) {
	rules, err := core.LoadJSONL(ruleResults)
	if err != nil {
		return nil, err
	}
	preds, err := ReadPredictions(mlPredictions)
	if err != nil {
		return nil, err
	}
	predIndex := map[string]int{}
	for i, row := range preds {
		for _, key := range core.RowKeys(row) {
			if _, ok := predIndex[key]; !ok {
				predIndex[key] = i
			}
		}
	}
	includeDL := dlPredictions != ""
	dlRows := []map[string]any{}
	if includeDL {
		dlRows, err = AggregateDLPredictions(dlPredictions, 3, 0.85)
		if err != nil {
			return nil, err
		}
	}
	dlIndex := map[string]int{}
	for i, row := range dlRows {
		for _, key := range core.RowKeys(row) {
			if _, ok := dlIndex[key]; !ok {
				dlIndex[key] = i
			}
		}
	}

	rows := []map[string]any{}
	matchedPred := map[int]bool{}
	matchedDL := map[int]bool{}
	for _, rule := range rules {
		predID := -1
		for _, key := range core.RowKeys(rule) {
			if id, ok := predIndex[key]; ok {
				predID = id
				matchedPred[id] = true
				break
			}
		}
		ml := map[string]any{}
		if predID >= 0 {
			ml = preds[predID]
		}
		dlID := -1
		for _, key := range core.RowKeys(rule) {
			if id, ok := dlIndex[key]; ok {
				dlID = id
				break
			}
		}
		if dlID < 0 && len(ml) > 0 {
			for _, key := range core.RowKeys(ml) {
				if id, ok := dlIndex[key]; ok {
					dlID = id
					break
				}
			}
		}
		dl := map[string]any{}
		if dlID >= 0 {
			dl = dlRows[dlID]
			matchedDL[dlID] = true
		}
		rows = append(rows, FuseOne(rule, ml, dl, includeDL))
	}
	for i, pred := range preds {
		if matchedPred[i] {
			continue
		}
		dlID := -1
		for _, key := range core.RowKeys(pred) {
			if id, ok := dlIndex[key]; ok {
				dlID = id
				break
			}
		}
		dl := map[string]any{}
		if dlID >= 0 {
			dl = dlRows[dlID]
			matchedDL[dlID] = true
		}
		rows = append(rows, FuseOne(map[string]any{}, pred, dl, includeDL))
	}
	for i, dl := range dlRows {
		if !matchedDL[i] {
			rows = append(rows, FuseOne(map[string]any{}, map[string]any{}, dl, includeDL))
		}
	}
	preferred := []string{"sample_id", "source_archive", "pcap_member", "file_name", "final_verdict", "final_confidence", "rule_verdict", "rule_confidence", "ml_prob_vpn", "ml_pred_label", "decision_reason_code", "review_recommended"}
	if err := core.WriteCSV(outPath, rows, preferred); err != nil {
		return nil, err
	}
	if csvOut != "" {
		if err := core.WriteCSV(csvOut, rows, preferred); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func AggregateDLPredictions(path string, topK int, threshold float64) ([]map[string]any, error) {
	rows, err := ReadPredictions(path)
	if err != nil {
		return nil, err
	}
	groups := map[string][]map[string]any{}
	for _, row := range rows {
		sampleID := core.ToString(row["sample_id"])
		if sampleID == "" {
			return nil, fmt.Errorf("DL predictions must contain sample_id")
		}
		groups[sampleID] = append(groups[sampleID], row)
	}
	keys := []string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []map[string]any{}
	for _, sampleID := range keys {
		group := groups[sampleID]
		probs := []float64{}
		for _, row := range group {
			probs = append(probs, core.SafeFloat(row["dl_prob_vpn"]))
		}
		sort.Slice(probs, func(i, j int) bool { return probs[i] > probs[j] })
		maximum := 0.0
		if len(probs) > 0 {
			maximum = probs[0]
		}
		topMean := 0.0
		limit := topK
		if limit > len(probs) {
			limit = len(probs)
		}
		for i := 0; i < limit; i++ {
			topMean += probs[i]
		}
		if limit > 0 {
			topMean /= float64(limit)
		}
		high := 0
		for _, p := range probs {
			if p >= threshold {
				high++
			}
		}
		row := copyMap(group[0])
		row["sample_id"] = sampleID
		row["dl_prob_vpn"] = maximum
		row["dl_pred_label"] = boolToInt(maximum >= 0.5)
		row["dl_evidence_count"] = len(group)
		row["dl_top_k_mean_prob_vpn"] = topMean
		row["dl_high_risk_flow_count"] = high
		out = append(out, row)
	}
	return out, nil
}

func isNumber(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	_, err := fmt.Sscanf(s, "%f", new(float64))
	return err == nil
}

func firstAny(values ...any) any {
	for _, v := range values {
		s := core.ToString(v)
		if s != "" && !strings.EqualFold(s, "nan") {
			return v
		}
	}
	return ""
}

func jsonString(v any) string {
	if v == nil {
		return "[]"
	}
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(strings.TrimSpace(x), "[") || strings.HasPrefix(strings.TrimSpace(x), "{") {
			return x
		}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func round(v float64, digits int) float64 {
	pow := 1.0
	for i := 0; i < digits; i++ {
		pow *= 10
	}
	return math.Round(v*pow) / pow
}

func copyMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

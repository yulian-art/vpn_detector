package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func DetectOne(rec map[string]any) DetectionResult {
	f := AnyMap(rec["file_feature"])
	engine := NewRuleEngine()
	scorer := ComboScorer{}
	matches := engine.Match(f)
	matchedIDs := []string{}
	high := []RuleMatch{}
	for _, m := range matches {
		matchedIDs = append(matchedIDs, m.RuleID)
		if m.Confidence >= 90 {
			high = append(high, m)
		}
	}

	verdict := "no_vpn_evidence"
	confidence := 0
	var comboScore *int
	comboDetail := map[string]int{}
	evidence := []string{}

	if len(high) > 0 {
		verdict = "vpn_confirmed"
		for _, m := range high {
			if m.Confidence > confidence {
				confidence = m.Confidence
			}
			if m.Evidence != "" {
				evidence = append(evidence, m.Evidence)
			}
		}
	} else {
		scores, comboEvidence := scorer.Score(f)
		total := scores.Total()
		if len(matches) > 0 {
			total += len(matches)
		}
		for _, m := range matches {
			if m.Evidence != "" {
				comboEvidence = append(comboEvidence, m.Evidence)
			}
		}
		switch {
		case total >= 14:
			verdict = "vpn_confirmed"
			confidence = minInt(94, 85+total)
		case total >= 10:
			verdict = "vpn_suspected"
			confidence = minInt(84, 70+total*2)
		case total >= 8:
			verdict = "weak_suspicious"
			confidence = minInt(69, 55+total*3)
		default:
			verdict = "no_vpn_evidence"
			confidence = 0
		}
		comboScore = &total
		comboDetail = scores.Map()
		evidence = comboEvidence
	}

	if len(evidence) > 20 {
		evidence = evidence[:20]
	}
	family := ""
	if verdict != "no_vpn_evidence" {
		family = InferVPNFamily(f, strings.Join(evidence, " "))
	}
	bestBlock, bestBlockRatio := MaxBlockRatio(f)
	sourceArchive := ToString(f["source_archive"])
	pcapMember := ToString(f["pcap_member"])
	fileName := ToString(f["file_name"])
	return DetectionResult{
		SourceArchive:       sourceArchive,
		PcapMember:          pcapMember,
		FileName:            fileName,
		SampleID:            ToString(f["sample_id"]),
		CaptureID:           ToString(f["capture_id"]),
		SplitGroup:          ToString(f["split_group"]),
		Verdict:             verdict,
		VPNFamily:           family,
		Confidence:          confidence,
		RiskScore:           round2(float64(confidence) / 10.0),
		MatchedRules:        matchedIDs,
		ComboScore:          comboScore,
		ComboDetail:         comboDetail,
		Evidence:            evidence,
		TopEndpoint:         ToString(f["top_endpoint"]),
		TopEndpointRatio:    SafeFloat(f["top_endpoint_ratio"]),
		TopSNI:              firstPairsAny(f["sni_top"], 5),
		TopDNS:              firstPairsAny(f["dns_top"], 5),
		DominantPayloadSize: SafeInt(f["dominant_payload_size"]),
		DominantPayloadRate: SafeFloat(f["dominant_payload_ratio"]),
		BestBlock:           bestBlock,
		BestBlockRatio:      bestBlockRatio,
		Notes:               ToString(f["extract_error"]),
	}
}

func RunDetection(featuresPath, outputPath, excelPath string) ([]DetectionResult, error) {
	rows, err := LoadJSONL(featuresPath)
	if err != nil {
		return nil, err
	}
	results := make([]DetectionResult, 0, len(rows))
	outAny := make([]any, 0, len(rows))
	for _, row := range rows {
		result := DetectOne(row)
		results = append(results, result)
		outAny = append(outAny, result)
	}
	if err := WriteJSONL(outputPath, outAny); err != nil {
		return nil, err
	}
	if excelPath != "" {
		csvPath := excelPath
		if strings.EqualFold(filepath.Ext(csvPath), ".xlsx") || strings.EqualFold(filepath.Ext(csvPath), ".xls") {
			csvPath = strings.TrimSuffix(csvPath, filepath.Ext(csvPath)) + ".csv"
		}
		if err := WriteDetectionCSV(csvPath, results); err != nil {
			return nil, err
		}
	}
	return results, nil
}

func WriteDetectionCSV(path string, results []DetectionResult) error {
	rows := make([]map[string]any, 0, len(results))
	for _, r := range results {
		bRules, _ := json.Marshal(r.MatchedRules)
		bDetail, _ := json.Marshal(r.ComboDetail)
		bEvidence, _ := json.Marshal(r.Evidence)
		bSNI, _ := json.Marshal(r.TopSNI)
		bDNS, _ := json.Marshal(r.TopDNS)
		rows = append(rows, map[string]any{
			"source_archive":         r.SourceArchive,
			"pcap_member":            r.PcapMember,
			"file_name":              r.FileName,
			"sample_id":              r.SampleID,
			"capture_id":             r.CaptureID,
			"split_group":            r.SplitGroup,
			"verdict":                r.Verdict,
			"vpn_family":             r.VPNFamily,
			"confidence":             r.Confidence,
			"risk_score":             r.RiskScore,
			"matched_rules":          string(bRules),
			"combo_score":            r.ComboScoreValue(),
			"combo_detail":           string(bDetail),
			"evidence":               string(bEvidence),
			"top_endpoint":           r.TopEndpoint,
			"top_endpoint_ratio":     r.TopEndpointRatio,
			"top_sni":                string(bSNI),
			"top_dns":                string(bDNS),
			"dominant_payload_size":  r.DominantPayloadSize,
			"dominant_payload_ratio": r.DominantPayloadRate,
			"best_block":             r.BestBlock,
			"best_block_ratio":       r.BestBlockRatio,
			"notes":                  r.Notes,
		})
	}
	return WriteCSV(path, rows, []string{
		"source_archive", "pcap_member", "file_name", "sample_id", "capture_id", "split_group",
		"verdict", "vpn_family", "confidence", "risk_score", "matched_rules", "combo_score",
		"combo_detail", "evidence", "top_endpoint", "top_endpoint_ratio", "top_sni", "top_dns",
		"dominant_payload_size", "dominant_payload_ratio", "best_block", "best_block_ratio", "notes",
	})
}

func (r DetectionResult) ComboScoreValue() any {
	if r.ComboScore == nil {
		return ""
	}
	return *r.ComboScore
}

func firstPairsAny(v any, n int) any {
	pairs := FlattenPairs(v)
	if len(pairs) == 0 {
		return []any{}
	}
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	out := make([][]any, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, []any{p.Key, p.Count})
	}
	return out
}

func LoadFeatureFile(path string) ([]map[string]any, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("features file not found: %s", path)
	}
	return LoadJSONL(path)
}

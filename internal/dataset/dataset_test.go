package dataset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vpn_detector/internal/core"
)

func TestBuildDatasetWeakSampleWeight(t *testing.T) {
	dir := t.TempDir()
	features := filepath.Join(dir, "features.jsonl")
	rec := map[string]any{
		"file_feature": map[string]any{
			"source_archive":     "",
			"pcap_member":        "a.pcapng",
			"file_name":          "a.pcapng",
			"file_size_bytes":    10,
			"total_packets":      100,
			"tcp_packets":        90,
			"udp_packets":        10,
			"top_endpoint_ratio": 0.8,
			"sni_top":            []any{[]any{"vpn.example", 3}},
			"dns_top":            []any{[]any{"vpn.example", 3}},
			"port_counts_top":    []any{[]any{"443", 50}},
			"block_1300_ratio":   0.2,
		},
		"top_flows": []any{},
	}
	line, _ := json.Marshal(rec)
	if err := os.WriteFile(features, append(line, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	labelsPath := filepath.Join(dir, "labels.csv")
	labelRows := []map[string]any{{
		"file_name":        "a.pcapng",
		"pcap_member":      "a.pcapng",
		"label_binary":     1,
		"label_confidence": "weak",
		"label_tool":       "MockVPN",
		"label_protocol":   "TLS_Tunnel",
		"split_group":      "g1",
	}}
	if err := core.WriteCSV(labelsPath, labelRows, []string{"file_name", "pcap_member", "label_binary", "label_confidence", "label_tool", "label_protocol", "split_group"}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "dataset.csv")
	rows, err := BuildDataset(features, labelsPath, out, "", false, "v", "l")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d, want 1", len(rows))
	}
	if rows[0]["sample_weight"] != 0.35 {
		t.Fatalf("sample_weight=%v, want 0.35", rows[0]["sample_weight"])
	}
	if rows[0]["split_group"] != "g1" {
		t.Fatalf("split_group=%v, want g1", rows[0]["split_group"])
	}
}

func TestNoIdentityExcludesObviousLeaks(t *testing.T) {
	rows := []map[string]any{{
		"label_binary":         1,
		"domain_kw_vpn":        1,
		"sni_unique_count":     1,
		"port_exact_443_count": 5,
		"pkt_total_packets":    10,
	}}
	cols := FeatureColumns(rows, "no_identity")
	if !contains(cols, "pkt_total_packets") {
		t.Fatalf("columns=%v, missing pkt_total_packets", cols)
	}
	for _, leak := range []string{"domain_kw_vpn", "sni_unique_count", "port_exact_443_count"} {
		if contains(cols, leak) {
			t.Fatalf("columns=%v, should exclude %s", cols, leak)
		}
	}
}

func contains(values []string, needle string) bool {
	for _, v := range values {
		if v == needle {
			return true
		}
	}
	return false
}

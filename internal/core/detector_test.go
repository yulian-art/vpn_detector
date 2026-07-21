package core

import "testing"

func TestDetectOneFixedBlockConfirmed(t *testing.T) {
	rec := map[string]any{
		"file_feature": map[string]any{
			"source_archive":        "",
			"pcap_member":           "vpn_sample.pcapng",
			"file_name":             "vpn_sample.pcapng",
			"total_payload_bytes":   20000,
			"block_1300_ratio":      0.42,
			"tls_clienthello_count": 0,
			"port_counts_top":       []any{[]any{"8388", 10}},
		},
	}
	result := DetectOne(rec)
	if result.Verdict != "vpn_confirmed" {
		t.Fatalf("verdict=%s, want vpn_confirmed", result.Verdict)
	}
	if result.Confidence < 90 {
		t.Fatalf("confidence=%d, want >= 90", result.Confidence)
	}
	if !contains(result.MatchedRules, "R_BLOCK_1300_SSR") {
		t.Fatalf("matched rules=%v, missing R_BLOCK_1300_SSR", result.MatchedRules)
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

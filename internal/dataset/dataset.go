package dataset

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vpn_detector/internal/core"
	"vpn_detector/internal/labels"
)

var MetaColumns = map[string]bool{
	"sample_id": true, "capture_id": true, "source_archive": true, "pcap_member": true, "file_name": true,
	"label_binary": true, "label_protocol": true, "label_tool": true, "label_family": true, "vpn_family": true, "scenario": true,
	"is_vpn": true, "need_review": true, "review_status": true, "label_status": true, "label_confidence": true,
	"sample_weight": true, "split_group": true, "feature_version": true, "label_version": true, "note": true,
	"size_bytes": true, "feature_set_hint": true, "device_id": true, "network_id": true, "time_period": true,
	"source_path": true, "label_score": true, "positive_votes": true, "negative_votes": true, "conflict_reasons": true,
	"evidence_json": true,
}

var IdentityPrefixes = []string{"id_", "domain_kw_", "sni_", "dns_", "ip_", "asn_", "port_exact_"}
var BehaviorPrefixes = []string{"flow_", "pkt_", "iat_", "bytes_", "ratio_", "block_", "mtu_", "duration_", "endpoint_", "payload_", "tcp_", "udp_", "quic_", "wpad_", "random_local_", "single_flow_", "long_flow_", "dominant_", "top_endpoint_ratio"}
var TLSPrefixes = []string{"tls_", "ja3_", "ja4_", "cipher_", "alpn_"}
var DNSPrefixes = []string{"dns_", "domain_", "risk_tld_", "random_local_", "wpad_"}
var PortPrefixes = []string{"port_", "port_exact_", "special_port_"}

func FlattenFeatureRecord(rec map[string]any) map[string]any {
	f := core.AnyMap(rec["file_feature"])
	flowsRaw, _ := rec["top_flows"].([]any)
	row := map[string]any{
		"source_archive": core.ToString(f["source_archive"]),
		"pcap_member":    core.ToString(f["pcap_member"]),
		"file_name":      core.ToString(f["file_name"]),
	}
	row["sample_id"] = firstString(core.ToString(f["sample_id"]), core.MakeSampleID(row["source_archive"], row["pcap_member"], row["file_name"], f["file_size_bytes"]))
	for key, val := range f {
		if key == "source_archive" || key == "pcap_member" || key == "file_name" || key == "extract_error" {
			continue
		}
		switch val.(type) {
		case map[string]any, []any, []map[string]any, []core.Pair:
			continue
		default:
			if isNumericLike(val) {
				row[key] = numericValue(val)
			}
		}
	}
	aliases := map[string]string{
		"total_packets":                "pkt_total_packets",
		"tcp_packets":                  "pkt_tcp_packets",
		"udp_packets":                  "pkt_udp_packets",
		"top_endpoint_ratio":           "endpoint_top_ratio",
		"single_flow_dominance":        "flow_single_dominance",
		"max_flow_duration":            "duration_max_flow",
		"max_flow_iat_under_1ms_ratio": "iat_max_flow_under_1ms_ratio",
		"mtu_fill_ratio":               "mtu_file_fill_ratio",
		"dominant_payload_size":        "payload_dominant_size",
		"dominant_payload_ratio":       "payload_dominant_ratio",
		"tls_clienthello_count":        "tls_clienthello_count",
		"alpn_missing_ratio":           "alpn_missing_ratio",
		"nonstandard_tls_flow_count":   "tls_nonstandard_flow_count",
		"cipher_suite_unique_count":    "cipher_suite_unique_count",
		"random_local_domain_count":    "random_local_domain_count",
		"wpad_query_count":             "wpad_query_count",
		"quic_frame_count":             "quic_frame_count",
		"no_tls_large_flow_count":      "tcp_no_tls_large_flow_count",
		"top_endpoint_ratio_duplicate": "top_endpoint_ratio_duplicate",
		"single_flow_dominance_alias":  "single_flow_dominance_alias",
		"dominant_payload_ratio_alias": "dominant_payload_ratio_alias",
	}
	for src, dst := range aliases {
		if _, ok := f[src]; ok {
			row[dst] = core.SafeFloat(f[src])
		}
	}

	totalPackets := core.SafeFloat(f["total_packets"])
	if totalPackets == 0 {
		totalPackets = 1
	}
	specialCount := 0
	for _, pair := range core.FlattenPairs(f["port_counts_top"]) {
		port := core.SafeInt(pair.Key)
		if port == 0 {
			continue
		}
		if core.SpecialPorts[port] || core.StandardTLSPorts[port] || map[int]bool{53: true, 80: true, 22: true, 3306: true, 500: true, 4500: true}[port] {
			row[fmt.Sprintf("port_exact_%d_count", port)] = pair.Count
			row[fmt.Sprintf("port_exact_%d_ratio", port)] = float64(pair.Count) / totalPackets
		}
		if core.SpecialPorts[port] {
			specialCount++
		}
	}
	row["special_port_unique_count"] = specialCount

	domains := pairNames(f["sni_top"])
	domains = append(domains, pairNames(f["dns_top"])...)
	row["domain_unique_count"] = len(unique(domains))
	row["sni_unique_count"] = len(unique(pairNames(f["sni_top"])))
	row["dns_unique_count"] = len(unique(pairNames(f["dns_top"])))
	for _, kw := range core.DomainKeywords {
		safe := safeColumn(kw)
		row["domain_kw_"+safe] = boolInt(anyContains(domains, strings.ToLower(kw)))
	}
	for _, tld := range core.RiskTLDs {
		safe := strings.ReplaceAll(strings.TrimPrefix(tld, "."), ".", "_")
		row["dns_tld_"+safe+"_present"] = boolInt(anySuffix(domains, tld))
	}

	ja4List := pairNames(f["ja4_top"])
	row["ja4_unique_count"] = len(unique(ja4List))
	cipherCounts := []int{}
	for _, ja4 := range ja4List {
		if c, ok := core.ExtractJA4CipherCount(ja4); ok {
			cipherCounts = append(cipherCounts, c)
		}
	}
	row["ja4_cipher_count_max"] = maxInts(cipherCounts)
	row["ja4_cipher_count_min"] = minInts(cipherCounts)
	row["ja4_has_t13d19"] = boolInt(prefixAny(ja4List, "t13d19"))
	row["ja4_has_t13d17"] = boolInt(prefixAny(ja4List, "t13d17"))
	row["ja4_has_t10"] = boolInt(prefixAny(ja4List, "t10"))
	row["ja4_has_chrome_like"] = boolInt(regexAny(ja4List, `^t13d151[0-9]h`))
	row["ja4_has_go_like"] = boolInt(regexAny(ja4List, `^t13d1011h2`))

	bestBlock, bestRatio := 0, 0.0
	for _, n := range core.BlockSizes {
		r := core.SafeFloat(f[fmt.Sprintf("block_%d_ratio", n)])
		row[fmt.Sprintf("block_%d_ratio", n)] = r
		if r > bestRatio {
			bestBlock, bestRatio = n, r
		}
	}
	row["block_best_size"] = bestBlock
	row["block_best_ratio"] = bestRatio

	if len(flowsRaw) > 0 {
		row["flow_top_count_exported"] = len(flowsRaw)
		row["flow_top_max_duration"] = maxFlow(flowsRaw, "duration")
		row["flow_top_max_iat_under_1ms_ratio"] = maxFlow(flowsRaw, "iat_under_1ms_ratio")
		row["flow_top_max_mtu_fill_ratio"] = maxFlow(flowsRaw, "mtu_fill_ratio")
		row["flow_top_max_ul_dl_ratio"] = finiteMaxFlow(flowsRaw, "ul_dl_ratio")
	} else {
		row["flow_top_count_exported"] = 0
	}

	prot := strings.ToLower(strings.Join(mapKeys(core.AnyMap(f["protocol_counts"])), " "))
	for _, name := range []string{"tls", "quic", "wg", "isakmp", "ike", "esp", "http", "dns"} {
		row["protocol_has_"+name] = boolInt(strings.Contains(prot, name))
	}
	return row
}

func BuildDataset(featuresPath string, labelsPath string, outPath string, csvOut string, includeUnlabeled bool, featureVersion, labelVersion string) ([]map[string]any, error) {
	features, err := core.LoadFeatureFile(featuresPath)
	if err != nil {
		return nil, err
	}
	labelRows := []map[string]string{}
	if labelsPath != "" {
		labelRows, err = core.ReadTable(labelsPath)
		if err != nil {
			return nil, err
		}
	}
	index := indexLabels(labelRows)
	rows := []map[string]any{}
	for _, rec := range features {
		row := FlattenFeatureRecord(rec)
		for k, v := range mergeLabel(row, index) {
			row[k] = v
		}
		row["feature_version"] = featureVersion
		row["label_version"] = labelVersion
		if includeUnlabeled || labels.NormalizeConfidence(row["label_confidence"]) != "unlabeled" {
			rows = append(rows, row)
		}
	}
	ordered := []string{"sample_id", "capture_id", "split_group", "source_archive", "pcap_member", "file_name", "label_binary", "label_protocol", "label_tool", "label_family", "scenario", "label_confidence", "sample_weight", "review_status", "label_status", "feature_version", "label_version", "need_review", "note"}
	if err := core.WriteCSV(outPath, rows, ordered); err != nil {
		return nil, err
	}
	if csvOut != "" {
		if err := core.WriteCSV(csvOut, rows, ordered); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func FeatureColumns(rows []map[string]any, featureSet string) []string {
	seen := map[string]bool{}
	for _, row := range rows {
		for k, v := range row {
			if MetaColumns[k] || !isNumericLike(v) {
				continue
			}
			seen[k] = true
		}
	}
	cols := []string{}
	for col := range seen {
		switch featureSet {
		case "all":
			cols = append(cols, col)
		case "no_identity":
			l := strings.ToLower(col)
			if startsWithAny(col, IdentityPrefixes) || strings.Contains(l, "sni") || strings.Contains(l, "domain_kw") || strings.Contains(l, "dns_tld") || strings.Contains(l, "ip_") || strings.Contains(l, "asn_") || strings.Contains(l, "endpoint_ip") {
				continue
			}
			cols = append(cols, col)
		case "behavior_only":
			if startsWithAny(col, BehaviorPrefixes) {
				cols = append(cols, col)
			}
		case "tls_only":
			if startsWithAny(col, TLSPrefixes) {
				cols = append(cols, col)
			}
		case "dns_only":
			if startsWithAny(col, DNSPrefixes) {
				cols = append(cols, col)
			}
		case "port_only":
			if startsWithAny(col, PortPrefixes) {
				cols = append(cols, col)
			}
		}
	}
	sort.Strings(cols)
	return cols
}

func LoadDatasetRows(path string) ([]map[string]any, error) {
	raw, err := core.ReadTable(path)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, row := range raw {
		m := map[string]any{}
		for k, v := range row {
			if isNumericString(v) {
				m[k] = core.SafeFloat(v)
			} else {
				m[k] = v
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func indexLabels(rows []map[string]string) map[string]map[string]string {
	index := map[string]map[string]string{}
	for _, row := range rows {
		for _, key := range rowKeysString(row) {
			if _, ok := index[key]; !ok {
				index[key] = row
			}
		}
	}
	return index
}

func rowKeysString(row map[string]string) []string {
	m := map[string]any{}
	for k, v := range row {
		m[k] = v
	}
	return core.RowKeys(m)
}

func mergeLabel(row map[string]any, index map[string]map[string]string) map[string]any {
	if len(index) == 0 {
		return map[string]any{
			"label_binary":     "",
			"label_protocol":   "unknown_protocol",
			"label_tool":       "unknown_tool",
			"label_family":     "",
			"label_confidence": "unlabeled",
			"sample_weight":    0.0,
			"capture_id":       row["sample_id"],
			"split_group":      row["sample_id"],
			"scenario":         "unknown",
			"need_review":      "yes",
		}
	}
	var lab map[string]string
	for _, key := range core.RowKeys(row) {
		if hit, ok := index[key]; ok {
			lab = hit
			break
		}
	}
	if lab == nil {
		return map[string]any{
			"label_binary":     "",
			"label_protocol":   "unknown_protocol",
			"label_tool":       "unknown_tool",
			"label_family":     "",
			"label_confidence": "unlabeled",
			"sample_weight":    0.0,
			"capture_id":       row["sample_id"],
			"split_group":      row["sample_id"],
			"scenario":         "unknown",
			"need_review":      "yes",
		}
	}
	binary := lab["label_binary"]
	if binary == "" {
		binary = lab["is_vpn"]
	}
	if b, ok := labels.NormalizeBinaryLabel(binary); ok {
		binary = fmt.Sprint(b)
	} else {
		binary = ""
	}
	conf := labels.NormalizeConfidence(lab["label_confidence"])
	return map[string]any{
		"label_binary":     binary,
		"label_protocol":   firstString(lab["label_protocol"], "unknown_protocol"),
		"label_tool":       firstString(lab["label_tool"], lab["vpn_family"], "unknown_tool"),
		"label_family":     firstString(lab["label_family"], lab["vpn_family"], ""),
		"label_confidence": conf,
		"sample_weight":    labels.WeightForConfidence(conf),
		"capture_id":       firstString(lab["capture_id"], core.ToString(row["sample_id"])),
		"split_group":      firstString(lab["split_group"], lab["capture_id"], core.ToString(row["sample_id"])),
		"scenario":         firstString(lab["scenario"], "unknown"),
		"need_review":      lab["need_review"],
		"review_status":    lab["review_status"],
		"label_status":     lab["label_status"],
		"note":             lab["note"],
	}
}

func pairNames(v any) []string {
	out := []string{}
	for _, p := range core.FlattenPairs(v) {
		out = append(out, strings.ToLower(p.Key))
	}
	return out
}

func isNumericLike(v any) bool {
	switch v.(type) {
	case int, int64, float64, float32, bool:
		return true
	case string:
		return isNumericString(v.(string))
	default:
		return false
	}
}

func isNumericString(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	_, err := strconvParseFloat(s)
	return err == nil
}

func numericValue(v any) any {
	if b, ok := v.(bool); ok {
		if b {
			return 1
		}
		return 0
	}
	return core.SafeFloat(v)
}

func safeColumn(s string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_]+`)
	out := strings.Trim(re.ReplaceAllString(strings.ToLower(s), "_"), "_")
	if len(out) > 40 {
		return out[:40]
	}
	return out
}

func unique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func anyContains(values []string, needle string) bool {
	for _, v := range values {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func anySuffix(values []string, suffix string) bool {
	for _, v := range values {
		if strings.HasSuffix(v, suffix) {
			return true
		}
	}
	return false
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func maxInts(values []int) int {
	best := 0
	for _, v := range values {
		if v > best {
			best = v
		}
	}
	return best
}

func minInts(values []int) int {
	if len(values) == 0 {
		return 0
	}
	best := values[0]
	for _, v := range values[1:] {
		if v < best {
			best = v
		}
	}
	return best
}

func prefixAny(values []string, prefix string) bool {
	for _, v := range values {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

func regexAny(values []string, pattern string) bool {
	re := regexp.MustCompile(pattern)
	for _, v := range values {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

func maxFlow(flows []any, key string) float64 {
	best := 0.0
	for _, raw := range flows {
		f := core.AnyMap(raw)
		best = math.Max(best, core.SafeFloat(f[key]))
	}
	return best
}

func finiteMaxFlow(flows []any, key string) float64 {
	best := 0.0
	for _, raw := range flows {
		f := core.AnyMap(raw)
		x := core.SafeFloat(f[key])
		if !math.IsNaN(x) && !math.IsInf(x, 0) {
			best = math.Max(best, x)
		}
	}
	return best
}

func mapKeys(m map[string]any) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func firstString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" && !strings.EqualFold(v, "nan") {
			return v
		}
	}
	return ""
}

func startsWithAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func strconvParseFloat(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

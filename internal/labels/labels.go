package labels

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"vpn_detector/internal/core"
)

var MasterColumns = []string{
	"entity_level", "sample_id", "capture_id", "flow_id", "window_id",
	"file_name", "pcap_member", "source_archive", "label_binary",
	"label_protocol", "label_tool", "label_family", "scenario",
	"label_confidence", "label_score", "label_status", "review_status",
	"positive_votes", "negative_votes", "conflict_reasons", "evidence_json",
	"device_id", "network_id", "time_period", "split_group", "note",
}

var pcapExts = map[string]bool{".pcap": true, ".pcapng": true, ".cap": true}
var nonVPNHints = []string{"nonvpn", "non-vpn", "non_vpn", "normal", "benign", "novpn", "no-vpn"}
var vpnHints = []string{"vpn", "proxy", "clash", "wireguard", "openvpn", "shadowsocks", "vless", "vmess"}
var vpnVerdicts = map[string]bool{"vpn_confirmed": true, "vpn_suspected": true, "weak_suspicious": true}

type Vote struct {
	Source     string         `json:"source"`
	Task       string         `json:"task"`
	Value      any            `json:"value"`
	Confidence string         `json:"confidence"`
	Weight     float64        `json:"weight"`
	Evidence   map[string]any `json:"evidence,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Family     string         `json:"family,omitempty"`
}

func NewVote(source, task string, value any, confidence string, reason string) Vote {
	conf := NormalizeConfidence(confidence)
	return Vote{Source: source, Task: task, Value: value, Confidence: conf, Weight: WeightForConfidence(conf), Reason: reason}
}

func NormalizeConfidence(value any) string {
	s := strings.ToLower(strings.TrimSpace(core.ToString(value)))
	aliases := map[string]string{"high": "strong", "verified": "strong", "manual": "strong", "auto": "medium", "unknown": "unlabeled", "": "unlabeled", "nan": "unlabeled"}
	if v, ok := aliases[s]; ok {
		s = v
	}
	switch s {
	case "strong", "medium", "weak", "unlabeled":
		return s
	default:
		return "unlabeled"
	}
}

func WeightForConfidence(confidence string) float64 {
	switch NormalizeConfidence(confidence) {
	case "strong":
		return 1.0
	case "medium":
		return 0.7
	case "weak":
		return 0.35
	default:
		return 0
	}
}

func ConfidenceRank(confidence string) int {
	switch NormalizeConfidence(confidence) {
	case "strong":
		return 3
	case "medium":
		return 2
	case "weak":
		return 1
	default:
		return 0
	}
}

func NormalizeBinaryLabel(value any) (int, bool) {
	s := strings.ToLower(strings.TrimSpace(core.ToString(value)))
	switch s {
	case "", "nan", "none", "unknown", "unlabeled", "null":
		return 0, false
	case "1", "true", "vpn", "yes", "y", "positive":
		return 1, true
	case "0", "false", "nonvpn", "non-vpn", "non_vpn", "normal", "benign", "no", "n", "negative":
		return 0, true
	default:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, false
		}
		n := int(f)
		if f == float64(n) && (n == 0 || n == 1) {
			return n, true
		}
		return 0, false
	}
}

func IterInputSamples(paths []string) ([]map[string]any, error) {
	rows := []map[string]any{}
	for _, raw := range paths {
		path := filepath.Clean(raw)
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			children := []string{}
			if err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() {
					children = append(children, p)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			sort.Strings(children)
			for _, child := range children {
				addSamplesForFile(&rows, child)
			}
			continue
		}
		addSamplesForFile(&rows, path)
	}
	return rows, nil
}

func addSamplesForFile(rows *[]map[string]any, path string) {
	ext := strings.ToLower(filepath.Ext(path))
	if pcapExts[ext] {
		*rows = append(*rows, SampleFromPath(path))
		return
	}
	if ext == ".zip" {
		*rows = append(*rows, SamplesFromZip(path)...)
		return
	}
	if ext == ".csv" || ext == ".json" || ext == ".jsonl" || ext == ".xlsx" || ext == ".xls" || ext == ".parquet" {
		table, err := core.ReadTable(path)
		if err != nil {
			return
		}
		for _, row := range table {
			*rows = append(*rows, SampleFromManifestRow(row))
		}
	}
}

func SampleFromPath(path string) map[string]any {
	fileName := filepath.Base(path)
	size := int64(0)
	if st, err := os.Stat(path); err == nil {
		size = st.Size()
	}
	captureID := core.MakeCaptureID("", path, fileName)
	return map[string]any{
		"entity_level":   "file",
		"sample_id":      core.MakeSampleID("", path, fileName, size),
		"capture_id":     captureID,
		"source_archive": "",
		"pcap_member":    path,
		"file_name":      fileName,
		"device_id":      "unknown_device",
		"network_id":     "unknown_network",
		"time_period":    "unknown_time",
		"split_group":    core.MakeSplitGroup("", path, fileName, captureID),
		"note":           "",
	}
}

func SamplesFromZip(path string) []map[string]any {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return []map[string]any{}
	}
	defer zr.Close()
	rows := []map[string]any{}
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !pcapExts[strings.ToLower(filepath.Ext(file.Name))] {
			continue
		}
		fileName := filepath.Base(filepath.FromSlash(file.Name))
		captureID := core.MakeCaptureID(path, file.Name, fileName)
		rows = append(rows, map[string]any{
			"entity_level":   "file",
			"sample_id":      core.MakeSampleID(path, file.Name, fileName, file.FileInfo().Size()),
			"capture_id":     captureID,
			"source_archive": path,
			"pcap_member":    file.Name,
			"file_name":      fileName,
			"device_id":      "unknown_device",
			"network_id":     "unknown_network",
			"time_period":    "unknown_time",
			"split_group":    core.MakeSplitGroup(path, file.Name, fileName, captureID),
			"note":           "",
		})
	}
	return rows
}

func SampleFromManifestRow(row map[string]string) map[string]any {
	fileName := row["file_name"]
	if fileName == "" {
		fileName = filepath.Base(row["pcap_member"])
	}
	pcapMember := row["pcap_member"]
	if pcapMember == "" {
		pcapMember = fileName
	}
	sourceArchive := row["source_archive"]
	fileSize := row["file_size_bytes"]
	if fileSize == "" {
		fileSize = row["size_bytes"]
	}
	sampleID := row["sample_id"]
	if sampleID == "" {
		sampleID = core.MakeSampleID(sourceArchive, pcapMember, fileName, fileSize)
	}
	captureID := row["capture_id"]
	if captureID == "" {
		captureID = core.MakeCaptureID(sourceArchive, pcapMember, fileName)
	}
	out := map[string]any{}
	for k, v := range row {
		out[k] = v
	}
	out["entity_level"] = firstAny(row["entity_level"], "file")
	out["sample_id"] = sampleID
	out["capture_id"] = captureID
	out["source_archive"] = sourceArchive
	out["pcap_member"] = pcapMember
	out["file_name"] = fileName
	out["split_group"] = firstAny(row["split_group"], core.MakeSplitGroup(sourceArchive, pcapMember, fileName, captureID))
	return out
}

func LFVPNRoot(sample map[string]any, vpnRoot string) *Vote {
	if SampleUnderRoot(sample, vpnRoot) {
		vote := NewVote("vpn_root", "binary", 1, "strong", "pcap_or_source_archive_under_vpn_root")
		return &vote
	}
	return nil
}

func LFNonVPNRoot(sample map[string]any, nonVPNRoot string) *Vote {
	if SampleUnderRoot(sample, nonVPNRoot) {
		vote := NewVote("nonvpn_root", "binary", 0, "strong", "pcap_or_source_archive_under_nonvpn_root")
		return &vote
	}
	return nil
}

func LFPathKeywords(sample map[string]any) *Vote {
	text := SampleText(sample)
	for _, h := range nonVPNHints {
		if strings.Contains(text, h) {
			vote := NewVote("path_keywords", "binary", 0, "medium", "path_contains_nonvpn_hint")
			return &vote
		}
	}
	for _, h := range vpnHints {
		if strings.Contains(text, h) {
			vote := NewVote("path_keywords", "binary", 1, "weak", "path_contains_vpn_hint")
			return &vote
		}
	}
	return nil
}

func LFManifestFields(sample map[string]any) *Vote {
	value, ok := NormalizeBinaryLabel(firstAny(sample["label_binary"], sample["is_vpn"]))
	if !ok {
		return nil
	}
	status := strings.ToLower(core.ToString(firstAny(sample["label_status"], sample["label_source"])))
	confidence := "medium"
	if strings.Contains(status, "verified") || strings.Contains(status, "dir_") {
		confidence = "strong"
	}
	vote := NewVote("manifest_v4", "binary", value, confidence, "manifest_binary_field")
	return &vote
}

func LFRuleResults(row map[string]any) *Vote {
	verdict := strings.TrimSpace(core.ToString(firstAny(row["verdict"], row["rule_verdict"])))
	confidence := core.SafeFloat(firstAny(row["confidence"], row["rule_confidence"]))
	if vpnVerdicts[verdict] {
		level := "weak"
		if verdict == "vpn_confirmed" && confidence >= 85 {
			level = "medium"
		}
		vote := NewVote("rule_results", "binary", 1, level, "rule_verdict_"+verdict)
		vote.Family = core.ToString(row["vpn_family"])
		return &vote
	}
	if verdict == "no_vpn_evidence" {
		vote := NewVote("rule_results", "binary", 0, "weak", "rule_no_vpn_evidence")
		return &vote
	}
	return nil
}

func AggregateVotes(sample map[string]any, votes []Vote) map[string]any {
	row := map[string]any{}
	for _, col := range MasterColumns {
		row[col] = ""
	}
	for _, col := range []string{"entity_level", "sample_id", "capture_id", "file_name", "pcap_member", "source_archive", "device_id", "network_id", "time_period", "split_group", "note"} {
		row[col] = firstAny(sample[col], row[col])
	}
	row["entity_level"] = firstAny(row["entity_level"], "file")
	row["split_group"] = firstAny(row["split_group"], firstAny(row["capture_id"], row["sample_id"]))

	binaryVotes := []Vote{}
	for _, v := range votes {
		if v.Task == "binary" {
			if _, ok := NormalizeBinaryLabel(v.Value); ok {
				binaryVotes = append(binaryVotes, v)
			}
		}
	}
	pos, neg := 0, 0
	for _, v := range binaryVotes {
		value, _ := NormalizeBinaryLabel(v.Value)
		if value == 1 {
			pos++
		} else {
			neg++
		}
	}
	row["positive_votes"] = pos
	row["negative_votes"] = neg
	ev, _ := json.Marshal(votes)
	row["evidence_json"] = string(ev)

	conflicts := []string{}
	strongValues := map[int]bool{}
	for _, v := range binaryVotes {
		value, _ := NormalizeBinaryLabel(v.Value)
		if NormalizeConfidence(v.Confidence) == "strong" {
			strongValues[value] = true
		}
	}
	if len(strongValues) > 1 {
		row["label_confidence"] = "unlabeled"
		row["label_score"] = 0.0
		row["label_status"] = "conflict"
		row["review_status"] = "needs_conflict_review"
		conflicts = append(conflicts, "strong_binary_conflict")
	} else if len(binaryVotes) > 0 {
		scores := map[int]float64{0: 0, 1: 0}
		bestConf := map[int]string{0: "unlabeled", 1: "unlabeled"}
		for _, v := range binaryVotes {
			value, _ := NormalizeBinaryLabel(v.Value)
			scores[value] += v.Weight
			if ConfidenceRank(v.Confidence) > ConfidenceRank(bestConf[value]) {
				bestConf[value] = NormalizeConfidence(v.Confidence)
			}
		}
		if scores[0] == scores[1] {
			row["label_confidence"] = "unlabeled"
			row["label_score"] = scores[0]
			row["label_status"] = "conflict"
			row["review_status"] = "needs_conflict_review"
			conflicts = append(conflicts, "binary_vote_tie")
		} else {
			chosen := 0
			if scores[1] > scores[0] {
				chosen = 1
			}
			row["label_binary"] = chosen
			row["label_confidence"] = bestConf[chosen]
			row["label_score"] = mathRound(scores[chosen], 4)
			row["label_status"] = "auto"
			if bestConf[chosen] == "weak" {
				row["review_status"] = "needs_review"
			} else {
				row["review_status"] = "auto_labeled"
			}
		}
	} else {
		row["label_confidence"] = "unlabeled"
		row["label_score"] = 0.0
		row["label_status"] = "unlabeled"
		row["review_status"] = "needs_label"
	}
	for _, item := range []struct {
		task string
		col  string
	}{{"protocol", "label_protocol"}, {"tool", "label_tool"}, {"family", "label_family"}, {"scenario", "scenario"}} {
		value, conflict := aggregateMetadata(votes, item.task)
		row[item.col] = value
		if conflict {
			conflicts = append(conflicts, item.task+"_conflict")
		}
	}
	if row["label_binary"] == 0 {
		row["label_protocol"] = firstAny(row["label_protocol"], "NonVPN")
		row["label_tool"] = firstAny(row["label_tool"], "NonVPN")
		row["label_family"] = firstAny(row["label_family"], "NonVPN")
	} else if row["label_binary"] == 1 {
		row["label_protocol"] = firstAny(row["label_protocol"], "unknown_protocol")
		row["label_tool"] = firstAny(row["label_tool"], "unknown_tool")
	}
	row["conflict_reasons"] = strings.Join(unique(conflicts), ";")
	return row
}

func BuildLabelsMaster(inputPaths []string, outPath, reviewPath, vpnRoot, nonVPNRoot string, sidePaths []string) ([]map[string]any, error) {
	samples, err := IterInputSamples(inputPaths)
	if err != nil {
		return nil, err
	}
	sideIndex, err := LoadSideVotes(sidePaths)
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, sample := range samples {
		votes := []Vote{}
		for _, ptr := range []*Vote{LFVPNRoot(sample, vpnRoot), LFNonVPNRoot(sample, nonVPNRoot), LFPathKeywords(sample), LFManifestFields(sample)} {
			if ptr != nil {
				votes = append(votes, *ptr)
			}
		}
		votes = append(votes, MetadataVotes("manifest_v4", sample, "medium")...)
		for _, key := range core.RowKeys(sample) {
			votes = append(votes, sideIndex[key]...)
		}
		rows = append(rows, AggregateVotes(sample, votes))
	}
	if err := core.WriteCSV(outPath, rows, MasterColumns); err != nil {
		return nil, err
	}
	if reviewPath != "" {
		if err := core.WriteCSV(reviewPath, rows, MasterColumns); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func BuildManifest(inputPaths []string, outPath, vpnRoot, nonVPNRoot string) error {
	rows, err := BuildLabelsMaster(inputPaths, outPath, "", vpnRoot, nonVPNRoot, nil)
	if err != nil {
		return err
	}
	_ = rows
	return nil
}

func MetadataVotes(source string, row map[string]any, confidence string) []Vote {
	votes := []Vote{}
	mapping := map[string]string{"label_protocol": "protocol", "label_tool": "tool", "label_family": "family", "scenario": "scenario"}
	for col, task := range mapping {
		value := strings.TrimSpace(core.ToString(row[col]))
		if value != "" && !strings.EqualFold(value, "nan") && !strings.EqualFold(value, "unknown") && !strings.EqualFold(value, "none") {
			votes = append(votes, NewVote(source, task, value, confidence, source+"_"+col))
		}
	}
	return votes
}

func LoadSideVotes(paths []string) (map[string][]Vote, error) {
	out := map[string][]Vote{}
	for _, path := range paths {
		if path == "" {
			continue
		}
		table, err := core.ReadTable(path)
		if err != nil {
			return nil, err
		}
		for _, rowStr := range table {
			row := map[string]any{}
			for k, v := range rowStr {
				row[k] = v
			}
			votes := []Vote{}
			if vote := LFRuleResults(row); vote != nil {
				votes = append(votes, *vote)
			}
			votes = append(votes, MetadataVotes("side_table", row, "medium")...)
			for _, key := range core.RowKeys(row) {
				out[key] = append(out[key], votes...)
			}
		}
	}
	return out, nil
}

func SampleText(sample map[string]any) string {
	return strings.ToLower(strings.Join([]string{core.ToString(sample["source_archive"]), core.ToString(sample["pcap_member"]), core.ToString(sample["file_name"])}, " "))
}

func SampleUnderRoot(sample map[string]any, root string) bool {
	if root == "" {
		return false
	}
	return isUnder(core.ToString(sample["pcap_member"]), root) || isUnder(core.ToString(sample["source_archive"]), root)
}

func isUnder(pathText, root string) bool {
	if pathText == "" || root == "" {
		return false
	}
	pAbs, pErr := filepath.Abs(pathText)
	rAbs, rErr := filepath.Abs(root)
	if pErr == nil && rErr == nil {
		rel, err := filepath.Rel(rAbs, pAbs)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	p := strings.ToLower(filepath.ToSlash(pathText))
	r := strings.TrimRight(strings.ToLower(filepath.ToSlash(root)), "/")
	return strings.HasPrefix(p, r+"/")
}

func aggregateMetadata(votes []Vote, task string) (string, bool) {
	counts := map[string]float64{}
	for _, v := range votes {
		if v.Task != task {
			continue
		}
		value := strings.TrimSpace(core.ToString(v.Value))
		if value == "" {
			continue
		}
		counts[value] += v.Weight
	}
	if len(counts) == 0 {
		return "", false
	}
	bestScore := -1.0
	bestValues := []string{}
	for value, score := range counts {
		if score > bestScore {
			bestScore = score
			bestValues = []string{value}
		} else if score == bestScore {
			bestValues = append(bestValues, value)
		}
	}
	sort.Strings(bestValues)
	return bestValues[0], len(bestValues) > 1
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

func mathRound(v float64, digits int) float64 {
	pow := 1.0
	for i := 0; i < digits; i++ {
		pow *= 10
	}
	return float64(int(v*pow+0.5)) / pow
}

func DescribeOutput(path string) string {
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".parquet" || ext == ".xlsx" || ext == ".xls" {
		return fmt.Sprintf("%s (CSV-formatted in Go build)", path)
	}
	return path
}

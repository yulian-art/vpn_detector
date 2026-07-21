package core

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func ToString(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	default:
		return fmt.Sprint(v)
	}
}

func SafeInt(v any) int {
	switch x := v.(type) {
	case nil:
		return 0
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case float32:
		return int(x)
	case json.Number:
		i, err := strconv.Atoi(x.String())
		if err == nil {
			return i
		}
		f, _ := strconv.ParseFloat(x.String(), 64)
		return int(f)
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0
		}
		if strings.Contains(s, ",") {
			s = strings.SplitN(s, ",", 2)[0]
		}
		if strings.HasPrefix(s, "0x") {
			i, err := strconv.ParseInt(s[2:], 16, 64)
			if err == nil {
				return int(i)
			}
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0
		}
		return int(f)
	default:
		return SafeInt(fmt.Sprint(v))
	}
}

func SafeFloat(v any) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0
		}
		return x
	case float32:
		return float64(x)
	case json.Number:
		f, _ := strconv.ParseFloat(x.String(), 64)
		return f
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0
		}
		if strings.Contains(s, ",") {
			s = strings.SplitN(s, ",", 2)[0]
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0
		}
		return f
	default:
		return SafeFloat(fmt.Sprint(v))
	}
}

func SafeBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "1" || s == "true" || s == "yes" || s == "y"
	case int:
		return x != 0
	case float64:
		return x != 0
	default:
		return false
	}
}

func FlattenPairs(v any) []Pair {
	out := []Pair{}
	switch x := v.(type) {
	case []Pair:
		return append(out, x...)
	case [][]any:
		for _, item := range x {
			if len(item) >= 2 {
				out = append(out, Pair{Key: ToString(item[0]), Count: SafeInt(item[1])})
			}
		}
	case []any:
		for _, raw := range x {
			switch item := raw.(type) {
			case []any:
				if len(item) >= 2 {
					out = append(out, Pair{Key: ToString(item[0]), Count: SafeInt(item[1])})
				}
			case map[string]any:
				key := item["key"]
				if key == nil {
					key = item["name"]
				}
				count := item["count"]
				out = append(out, Pair{Key: ToString(key), Count: SafeInt(count)})
			}
		}
	}
	return out
}

func GetPorts(f Feature) map[int]int {
	ports := map[int]int{}
	for _, pair := range FlattenPairs(f["port_counts_top"]) {
		p := SafeInt(pair.Key)
		if p > 0 {
			ports[p] = pair.Count
		}
	}
	return ports
}

func AllDomains(f Feature) []string {
	out := []string{}
	for _, key := range []string{"sni_top", "dns_top"} {
		for _, pair := range FlattenPairs(f[key]) {
			if pair.Key != "" {
				out = append(out, strings.ToLower(pair.Key))
			}
		}
	}
	return out
}

func ProtocolText(f Feature) string {
	switch x := f["protocol_counts"].(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, strings.ToLower(k))
		}
		sort.Strings(keys)
		return strings.Join(keys, " ")
	case map[string]int:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, strings.ToLower(k))
		}
		sort.Strings(keys)
		return strings.Join(keys, " ")
	default:
		return strings.ToLower(ToString(f["protocol_counts"]))
	}
}

func MaxBlockRatio(f Feature) (int, float64) {
	bestN, bestR := 0, 0.0
	for _, n := range BlockSizes {
		r := SafeFloat(f[fmt.Sprintf("block_%d_ratio", n)])
		if r > bestR {
			bestN, bestR = n, r
		}
	}
	return bestN, bestR
}

func EntropyLabel(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	for _, c := range counts {
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func DomainEntropy(domain string) float64 {
	if domain == "" {
		return 0
	}
	return EntropyLabel(strings.Split(domain, ".")[0])
}

func CountUniqueTLDs(domains []string, riskTLDs []string) int {
	found := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(d)
		for _, tld := range riskTLDs {
			if strings.HasSuffix(d, tld) {
				found[tld] = true
			}
		}
	}
	return len(found)
}

func DetectRandomLocalDomains(pairs []Pair) int {
	count := 0
	for _, pair := range pairs {
		d := strings.ToLower(pair.Key)
		if !strings.HasSuffix(d, ".local") {
			continue
		}
		label := strings.Split(d, ".")[0]
		if len(label) >= 8 && EntropyLabel(label) >= 3.0 {
			count++
		}
	}
	return count
}

func ExtractJA4CipherCount(ja4 string) (int, bool) {
	re := regexp.MustCompile(`^t\d+d(\d{1,2})`)
	m := re.FindStringSubmatch(ja4)
	if len(m) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func DomainKeywordHits(domains []string) []string {
	hits := []string{}
	for _, d := range domains {
		for _, kw := range DomainKeywords {
			if strings.Contains(strings.ToLower(d), strings.ToLower(kw)) {
				hits = append(hits, d)
				break
			}
		}
	}
	sort.Strings(hits)
	return uniqueStrings(hits)
}

func DetectRegionalNodeNaming(domains []string) bool {
	for _, d := range domains {
		label := strings.Split(strings.ToLower(d), ".")[0]
		m := RegionalNodeRe.FindStringSubmatch(label)
		if len(m) >= 2 && ISOCountryCodes[strings.ToLower(m[1])] {
			return true
		}
	}
	return false
}

func RowKeys(row map[string]any) []string {
	keys := map[string]bool{}
	for _, col := range []string{"sample_id", "pcap_member", "file_name"} {
		text := strings.TrimSpace(ToString(row[col]))
		if text == "" || strings.EqualFold(text, "nan") {
			continue
		}
		lower := strings.ToLower(text)
		keys[lower] = true
		keys[strings.ToLower(filepath.Base(text))] = true
	}
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func MD5Short(parts ...any) string {
	raw := make([]string, 0, len(parts))
	for _, part := range parts {
		raw = append(raw, ToString(part))
	}
	sum := md5.Sum([]byte(strings.Join(raw, "|")))
	return hex.EncodeToString(sum[:])[:16]
}

func TopMapPairs(counter map[string]int, limit int) [][]any {
	pairs := make([]Pair, 0, len(counter))
	for k, v := range counter {
		pairs = append(pairs, Pair{Key: k, Count: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count == pairs[j].Count {
			return pairs[i].Key < pairs[j].Key
		}
		return pairs[i].Count > pairs[j].Count
	})
	if limit > 0 && len(pairs) > limit {
		pairs = pairs[:limit]
	}
	out := make([][]any, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, []any{p.Key, p.Count})
	}
	return out
}

func TopIntPairs(counter map[int]int, limit int) [][]any {
	pairs := make([]Pair, 0, len(counter))
	for k, v := range counter {
		pairs = append(pairs, Pair{Key: strconv.Itoa(k), Count: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count == pairs[j].Count {
			return pairs[i].Key < pairs[j].Key
		}
		return pairs[i].Count > pairs[j].Count
	})
	if limit > 0 && len(pairs) > limit {
		pairs = pairs[:limit]
	}
	out := make([][]any, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, []any{p.Key, p.Count})
	}
	return out
}

func uniqueStrings(values []string) []string {
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

func AnyMap(v any) Feature {
	if v == nil {
		return Feature{}
	}
	if f, ok := v.(Feature); ok {
		return f
	}
	if m, ok := v.(map[string]any); ok {
		return Feature(m)
	}
	return Feature{}
}

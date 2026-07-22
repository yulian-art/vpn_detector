package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// RuleConfigFile 对应仓库根目录 rules_config.json 的顶层结构。
// 这个结构是 Go 与 Python 共享配置的入口，新增常量或规则时先改 JSON。
type RuleConfigFile struct {
	Version   string            `json:"version"`
	Constants RuleConstants     `json:"constants"`
	Rules     []RuleConfigEntry `json:"rules"`
}

// RuleConstants 保存检测器会共同使用的端口、域名、正则和固定块常量。
// JSON 里用数组表达集合，Go 初始化时再转成 map[int]bool 或 map[string]bool。
type RuleConstants struct {
	BlockSizes            []int             `json:"block_sizes"`
	BlockFamily           map[string]string `json:"block_family"`
	StandardTLSPorts      []int             `json:"standard_tls_ports"`
	SpecialPorts          []int             `json:"special_ports"`
	DomainKeywords        []string          `json:"domain_keywords"`
	RiskTLDs              []string          `json:"risk_tlds"`
	JA4BrowserPatterns    []string          `json:"ja4_browser_patterns"`
	JA4NonBrowserPatterns []string          `json:"ja4_non_browser_patterns"`
	JA4GolangPattern      string            `json:"ja4_golang_pattern"`
	ChromeJA4Prefix       string            `json:"chrome_ja4_prefix"`
	ISOCountryCodes       []string          `json:"iso_country_codes"`
	FamousEnterpriseSNI   []string          `json:"famous_enterprise_sni"`
	VPNFamilyRules        []VPNFamilyConfig `json:"vpn_family_rules"`
}

// VPNFamilyConfig 保留配置中的家族推断信号，供后续继续把家族推断外置。
type VPNFamilyConfig struct {
	Signals []string `json:"signals"`
	Family  string   `json:"family"`
}

// RuleConfigEntry 保存一条规则的元数据和 detector 名称。
// detector 是跨语言稳定名称，Go/Python 分别映射到本地函数。
type RuleConfigEntry struct {
	ID          string         `json:"id"`
	Category    string         `json:"category"`
	Description string         `json:"description"`
	Confidence  int            `json:"confidence"`
	Detector    string         `json:"detector"`
	Enabled     *bool          `json:"enabled,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
}

var SharedRuleConfig = mustLoadRuleConfig()

func mustLoadRuleConfig() RuleConfigFile {
	cfg, err := LoadRuleConfig("")
	if err != nil {
		panic(err)
	}
	return cfg
}

// LoadRuleConfig 读取共享规则配置。
// explicitPath 为空时，按环境变量和目录向上查找 rules_config.json。
func LoadRuleConfig(explicitPath string) (RuleConfigFile, error) {
	for _, path := range ruleConfigCandidates(explicitPath) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg RuleConfigFile
		if err := json.Unmarshal(data, &cfg); err != nil {
			return RuleConfigFile{}, fmt.Errorf("parse %s: %w", path, err)
		}
		if len(cfg.Rules) == 0 || len(cfg.Constants.BlockSizes) == 0 {
			return RuleConfigFile{}, fmt.Errorf("invalid rule config: %s", path)
		}
		return cfg, nil
	}
	return RuleConfigFile{}, fmt.Errorf("rules_config.json not found; set VPN_DETECTOR_RULE_CONFIG")
}

func ruleConfigCandidates(explicitPath string) []string {
	if explicitPath != "" {
		return []string{explicitPath}
	}
	out := []string{}
	if env := os.Getenv("VPN_DETECTOR_RULE_CONFIG"); env != "" {
		out = append(out, env)
	}
	if cwd, err := os.Getwd(); err == nil {
		out = appendRuleConfigUpward(out, cwd)
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		out = appendRuleConfigUpward(out, filepath.Dir(file))
	}
	return uniquePaths(out)
}

func appendRuleConfigUpward(out []string, start string) []string {
	dir, err := filepath.Abs(start)
	if err != nil {
		dir = start
	}
	for i := 0; i < 8; i++ {
		out = append(out, filepath.Join(dir, "rules_config.json"))
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

func uniquePaths(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		clean := filepath.Clean(value)
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	return out
}

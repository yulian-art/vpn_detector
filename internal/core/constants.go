package core

import "regexp"

// 常量统一从共享 JSON 初始化，保留原来的变量名，减少其他包改动。
var BlockSizes = append([]int(nil), SharedRuleConfig.Constants.BlockSizes...)

var BlockFamily = intStringMap(SharedRuleConfig.Constants.BlockFamily)

var StandardTLSPorts = intSet(SharedRuleConfig.Constants.StandardTLSPorts)

var SpecialPorts = intSet(SharedRuleConfig.Constants.SpecialPorts)

var DomainKeywords = append([]string(nil), SharedRuleConfig.Constants.DomainKeywords...)

var RiskTLDs = append([]string(nil), SharedRuleConfig.Constants.RiskTLDs...)

var JA4BrowserPatterns = append([]string(nil), SharedRuleConfig.Constants.JA4BrowserPatterns...)

var JA4NonBrowserPatterns = append([]string(nil), SharedRuleConfig.Constants.JA4NonBrowserPatterns...)

var ISOCountryCodes = stringSet(SharedRuleConfig.Constants.ISOCountryCodes)

var FamousEnterpriseSNI = append([]string(nil), SharedRuleConfig.Constants.FamousEnterpriseSNI...)

var VPNFamilyRules = append([]VPNFamilyConfig(nil), SharedRuleConfig.Constants.VPNFamilyRules...)

var (
	// 正则表达式也从共享配置读取，避免 Python 与 Go 的 JA4 模式不一致。
	ChromeJA4Prefix = regexp.MustCompile(SharedRuleConfig.Constants.ChromeJA4Prefix)
	JA4GoPattern    = regexp.MustCompile(SharedRuleConfig.Constants.JA4GolangPattern)
	TLS10JA4        = regexp.MustCompile(`^t10d`)
	RegionalNodeRe  = regexp.MustCompile(`(?i)^([a-z]{2})\d+([-.]|$)`)
)

func intSet(values []int) map[int]bool {
	out := map[int]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func stringSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func intStringMap(values map[string]string) map[int]string {
	out := map[int]string{}
	for key, value := range values {
		out[SafeInt(key)] = value
	}
	return out
}

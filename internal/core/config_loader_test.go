package core

import "testing"

func TestSharedRuleConfigDrivesConstantsAndRules(t *testing.T) {
	// 这条测试确保 Go 侧确实从共享 JSON 读取常量和规则清单。
	if SharedRuleConfig.Version != "rules_config_v1" {
		t.Fatalf("version=%q, want rules_config_v1", SharedRuleConfig.Version)
	}
	if len(BlockSizes) == 0 || BlockSizes[0] != 1300 {
		t.Fatalf("block sizes=%v, want first size 1300", BlockSizes)
	}
	if !SpecialPorts[8388] || !StandardTLSPorts[443] {
		t.Fatalf("shared ports were not loaded: special=%v tls=%v", SpecialPorts[8388], StandardTLSPorts[443])
	}
	if len(AllRules()) != len(SharedRuleConfig.Rules) {
		t.Fatalf("rules=%d, config=%d", len(AllRules()), len(SharedRuleConfig.Rules))
	}
	if AllRules()[0].ID != SharedRuleConfig.Rules[0].ID {
		t.Fatalf("first rule=%q, config=%q", AllRules()[0].ID, SharedRuleConfig.Rules[0].ID)
	}
}

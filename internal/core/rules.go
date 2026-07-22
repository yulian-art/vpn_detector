package core

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

type RuleEngine struct {
	Rules []RuleDef
}

func NewRuleEngine() RuleEngine {
	return RuleEngine{Rules: AllRules()}
}

func (e RuleEngine) Match(f Feature) []RuleMatch {
	matches := []RuleMatch{}
	for _, rule := range e.Rules {
		if !rule.Enabled || rule.Detect == nil {
			continue
		}
		hit, evidence := rule.Detect(f)
		if hit {
			matches = append(matches, RuleMatch{
				RuleID:     rule.ID,
				Category:   rule.Category,
				Confidence: rule.Confidence,
				Evidence:   evidence,
			})
		}
	}
	return matches
}

func AllRules() []RuleDef {
	rules := make([]RuleDef, 0, len(SharedRuleConfig.Rules))
	for _, cfg := range SharedRuleConfig.Rules {
		rules = append(rules, buildRuleFromConfig(cfg))
	}
	return rules
}

func buildRuleFromConfig(cfg RuleConfigEntry) RuleDef {
	// detector 名称来自共享 JSON，Go 侧只负责绑定到本地实现函数。
	detect := resolveDetector(cfg)
	enabled := true
	if cfg.Enabled != nil {
		enabled = *cfg.Enabled
	}
	return RuleDef{
		ID:          cfg.ID,
		Category:    cfg.Category,
		Description: cfg.Description,
		Confidence:  cfg.Confidence,
		Detect:      detect,
		Enabled:     enabled,
	}
}

func resolveDetector(cfg RuleConfigEntry) func(Feature) (bool, string) {
	if cfg.Detector == "block_payload" {
		// 固定载荷块类规则共用模板，块大小和阈值由 JSON params 控制。
		return makeBlockDetector(SafeInt(cfg.Params["block_size"]), SafeFloat(cfg.Params["threshold"]), ToString(cfg.Params["label"]))
	}
	if detect, ok := detectorRegistry()[cfg.Detector]; ok {
		return detect
	}
	panic(fmt.Sprintf("unknown detector in rules_config.json: %s", cfg.Detector))
}

func makeBlockDetector(n int, threshold float64, label string) func(Feature) (bool, string) {
	return func(f Feature) (bool, string) {
		ratio := SafeFloat(f[fmt.Sprintf("block_%d_ratio", n)])
		if ratio >= threshold {
			return true, fmt.Sprintf("fixed payload block %d ratio %.2f (%s)", n, ratio, label)
		}
		return false, ""
	}
}

func detectorRegistry() map[string]func(Feature) (bool, string) {
	// 这张表是共享配置 detector 名称和 Go 检测函数之间的唯一映射。
	return map[string]func(Feature) (bool, string){
		"ipsec_esp":               detectIPSecESP,
		"ipsec_ah":                detectIPSecAH,
		"ipsec_esp_ah":            detectIPSecESPAH,
		"ipsec_ike":               detectIPSecIKE,
		"ipsec_natt":              detectIPSecNATT,
		"wireguard_port":          detectWireGuardPort,
		"wireguard_proto":         detectWireGuardProto,
		"openvpn":                 detectOpenVPN,
		"port_mismatch_3306":      detectPortMismatch3306,
		"special_port_encrypted":  detectSpecialPortEncrypted,
		"ssh_keepalive_probe":     detectSSHKeepalive,
		"p2p_dual_channel":        detectP2PDualChannel,
		"no_tls_encrypted_tcp":    detectNoTLSEncryptedTCP,
		"vpn_domain_sni":          detectVPNDomainSNI,
		"chrome_ja4_no_alpn":      detectChromeJA4NoALPN,
		"ja4_non_browser":         detectJA4NonBrowser,
		"ja4_golang":              detectJA4Go,
		"single_cipher_suite":     detectSingleCipherSuite,
		"tls_v1_0":                detectTLS10,
		"sni_ip_mismatch":         detectSNIIPMismatch,
		"single_sni_monopoly":     detectSingleSNIMonopoly,
		"regional_node_naming":    detectRegionalNodeNamingRule,
		"single_ja4_multi_sni":    detectSingleJA4MultiSNI,
		"block_1344_nordvpn":      detectBlock1344NordVPN,
		"wizvpn_1452":             detectWizVPN1452,
		"mdns_hola":               detectMDNSHola,
		"mdns_random_local":       detectRandomLocalDomainsRule,
		"wpad_storm":              detectWPADStorm,
		"cheap_tld_concentration": detectCheapTLDConcentration,
		"dns_gap_tcp_reachable":   detectDNSGapTCPReachable,
		"udp53_masquerade":        detectUDP53Masquerade,
		"nordvpn_dns_tunnel":      detectNordVPNDNSTunnel,
		"doh_present":             detectDOHPresent,
		"two_phase_connection":    detectTwoPhaseConnection,
		"quic_tls_dual":           detectQUICTLSDual,
		"extreme_flow_dominance":  detectExtremeFlowDominance,
	}
}

func detectIPSecESP(f Feature) (bool, string) {
	ip := AnyMap(f["ip_proto_counts"])
	esp := SafeInt(ip["50"])
	if esp > 0 {
		return true, fmt.Sprintf("IP protocol 50 ESP packets=%d", esp)
	}
	return false, ""
}

func detectIPSecAH(f Feature) (bool, string) {
	ip := AnyMap(f["ip_proto_counts"])
	ah := SafeInt(ip["51"])
	if ah > 0 {
		return true, fmt.Sprintf("IP protocol 51 AH packets=%d", ah)
	}
	return false, ""
}

func detectIPSecESPAH(f Feature) (bool, string) {
	ip := AnyMap(f["ip_proto_counts"])
	esp, ah := SafeInt(ip["50"]), SafeInt(ip["51"])
	if esp > 0 || ah > 0 {
		return true, fmt.Sprintf("ESP/AH packets: esp=%d ah=%d", esp, ah)
	}
	return false, ""
}

func detectIPSecIKE(f Feature) (bool, string) {
	prot := ProtocolText(f)
	if strings.Contains(prot, "isakmp") || strings.Contains(prot, "ike") || strings.Contains(prot, "ikev2") {
		return true, "tshark protocol column contains ISAKMP/IKE"
	}
	return false, ""
}

func detectIPSecNATT(f Feature) (bool, string) {
	if SafeBool(f["esp_in_udp_like"]) {
		return true, fmt.Sprintf("ESP-in-UDP over UDP 4500 count=%d", SafeInt(f["udp4500_count"]))
	}
	return false, ""
}

func detectWireGuardPort(f Feature) (bool, string) {
	ports := GetPorts(f)
	if ports[51820] > 0 {
		return true, fmt.Sprintf("WireGuard UDP port 51820 count=%d", ports[51820])
	}
	return false, ""
}

func detectWireGuardProto(f Feature) (bool, string) {
	if strings.Contains(ProtocolText(f), "wg") {
		return true, "tshark protocol column contains wg"
	}
	return false, ""
}

func detectOpenVPN(f Feature) (bool, string) {
	ports := GetPorts(f)
	hits := []int{}
	for _, p := range []int{1194, 1195} {
		if ports[p] > 0 {
			hits = append(hits, p)
		}
	}
	if len(hits) > 0 {
		return true, fmt.Sprintf("OpenVPN common ports hit=%v", hits)
	}
	return false, ""
}

func detectPortMismatch3306(f Feature) (bool, string) {
	ports := GetPorts(f)
	if ports[3306] > 0 && SafeFloat(f["block_1428_ratio"]) >= 0.50 && !strings.Contains(ProtocolText(f), "mysql") {
		return true, fmt.Sprintf("TCP 3306 without MySQL and block_1428_ratio=%.2f", SafeFloat(f["block_1428_ratio"]))
	}
	return false, ""
}

func detectSpecialPortEncrypted(f Feature) (bool, string) {
	ports := GetPorts(f)
	hits := []int{}
	for p := range ports {
		if SpecialPorts[p] {
			hits = append(hits, p)
		}
	}
	sort.Ints(hits)
	if len(hits) == 0 {
		return false, ""
	}
	_, bestRatio := MaxBlockRatio(f)
	if SafeInt(f["tls_clienthello_count"]) > 0 || bestRatio >= 0.30 || SafeInt(f["no_tls_large_flow_count"]) > 0 {
		return true, fmt.Sprintf("special ports %v with TLS/fixed-block/large encrypted flow evidence", hits)
	}
	return false, ""
}

func detectSSHKeepalive(f Feature) (bool, string) {
	ports := GetPorts(f)
	if SafeBool(f["ssh_syn_periodic"]) && SafeInt(f["ssh_syn_count"]) > 20 && ports[22] == 0 {
		return true, fmt.Sprintf("periodic SSH SYN keepalive count=%d", SafeInt(f["ssh_syn_count"]))
	}
	return false, ""
}

func detectP2PDualChannel(f Feature) (bool, string) {
	ports := GetPorts(f)
	if ports[22225] == 0 && ports[22226] == 0 {
		return false, ""
	}
	tlsCount := SafeInt(f["tls_clienthello_count"])
	noTLSLarge := SafeInt(f["no_tls_large_flow_count"])
	nonstandardTLS := SafeInt(f["nonstandard_tls_flow_count"])
	if tlsCount > 0 && noTLSLarge > 0 && (nonstandardTLS > 0 || tlsCount > 10) {
		return true, fmt.Sprintf("Hola-like dual channel tls=%d no_tls_large=%d", tlsCount, noTLSLarge)
	}
	return false, ""
}

func detectNoTLSEncryptedTCP(f Feature) (bool, string) {
	tlsCount := SafeInt(f["tls_clienthello_count"])
	nonstandardTLS := SafeInt(f["nonstandard_tls_flow_count"])
	bestBlock, bestRatio := MaxBlockRatio(f)
	totalPayload := SafeInt(f["total_payload_bytes"])
	if tlsCount <= 2 && nonstandardTLS == 0 && bestRatio >= 0.30 && totalPayload > 10000 {
		return true, fmt.Sprintf("no/low TLS encrypted TCP fixed block=%d ratio=%.2f", bestBlock, bestRatio)
	}
	return false, ""
}

func detectVPNDomainSNI(f Feature) (bool, string) {
	hits := DomainKeywordHits(AllDomains(f))
	if len(hits) > 0 {
		return true, "VPN domain keyword hit: " + strings.Join(firstN(hits, 10), ", ")
	}
	return false, ""
}

func detectChromeJA4NoALPN(f Feature) (bool, string) {
	if SafeFloat(f["alpn_missing_ratio"]) < 0.90 || SafeInt(f["tls_clienthello_count"]) == 0 {
		return false, ""
	}
	for _, pair := range FlattenPairs(f["ja4_top"]) {
		if ChromeJA4Prefix.MatchString(pair.Key) {
			return true, fmt.Sprintf("Chrome-like JA4 without ALPN: %s", pair.Key)
		}
	}
	return false, ""
}

func detectJA4NonBrowser(f Feature) (bool, string) {
	alpnMissing := SafeFloat(f["alpn_missing_ratio"])
	tlsCount := SafeInt(f["tls_clienthello_count"])
	for _, pair := range FlattenPairs(f["ja4_top"]) {
		cc, ok := ExtractJA4CipherCount(pair.Key)
		if !ok {
			continue
		}
		if cc >= 25 && alpnMissing >= 0.80 {
			return true, fmt.Sprintf("non-browser JA4 high cipher count=%d ja4=%s", cc, pair.Key)
		}
		if cc <= 6 && tlsCount > 0 {
			return true, fmt.Sprintf("TLS 1.0/low cipher JA4 count=%d ja4=%s", cc, pair.Key)
		}
		if (cc == 19 || cc == 17) && alpnMissing >= 0.80 {
			return true, fmt.Sprintf("VPN-like JA4 cipher count=%d ja4=%s", cc, pair.Key)
		}
	}
	return false, ""
}

func detectJA4Go(f Feature) (bool, string) {
	for _, pair := range FlattenPairs(f["ja4_top"]) {
		if JA4GoPattern.MatchString(pair.Key) {
			return true, fmt.Sprintf("Go TLS JA4 fingerprint %s", pair.Key)
		}
	}
	return false, ""
}

func detectSingleCipherSuite(f Feature) (bool, string) {
	if SafeInt(f["cipher_suite_unique_count"]) == 1 && ToString(f["single_cipher_suite"]) != "" && SafeInt(f["tls_clienthello_count"]) > 5 {
		return true, fmt.Sprintf("single cipher suite %s", ToString(f["single_cipher_suite"]))
	}
	return false, ""
}

func detectTLS10(f Feature) (bool, string) {
	for _, pair := range FlattenPairs(f["ja4_top"]) {
		if TLS10JA4.MatchString(pair.Key) {
			return true, fmt.Sprintf("TLS 1.0 JA4 %s", pair.Key)
		}
	}
	return false, ""
}

func detectSNIIPMismatch(f Feature) (bool, string) {
	topEndpoint := ToString(f["top_endpoint"])
	if topEndpoint == "" {
		return false, ""
	}
	for _, pair := range FlattenPairs(f["sni_top"]) {
		lower := strings.ToLower(pair.Key)
		for _, enterprise := range FamousEnterpriseSNI {
			if strings.Contains(lower, enterprise) {
				return true, fmt.Sprintf("enterprise SNI %s carried by endpoint %s", pair.Key, topEndpoint)
			}
		}
	}
	return false, ""
}

func detectSingleSNIMonopoly(f Feature) (bool, string) {
	sni := FlattenPairs(f["sni_top"])
	if len(sni) == 0 || SafeInt(f["tls_clienthello_count"]) < 10 {
		return false, ""
	}
	total := 0
	for _, p := range sni {
		total += p.Count
	}
	if total == 0 {
		return false, ""
	}
	top := sni[0]
	ratio := float64(top.Count) / float64(total)
	for _, svc := range []string{"googlemail.com", "gmail.com", "outlook.com", "office365.com", "microsoft.com", "amazonaws.com", "apple.com", "icloud.com"} {
		if strings.Contains(strings.ToLower(top.Key), svc) {
			return false, ""
		}
	}
	if ratio >= 0.90 && SafeFloat(f["alpn_missing_ratio"]) >= 0.80 && SafeInt(f["nonstandard_tls_flow_count"]) >= 10 {
		return true, fmt.Sprintf("single SNI monopoly %s ratio=%.2f", top.Key, ratio)
	}
	return false, ""
}

func detectRegionalNodeNamingRule(f Feature) (bool, string) {
	domains := AllDomains(f)
	if DetectRegionalNodeNaming(domains) {
		return true, "regional node naming pattern in SNI/DNS"
	}
	return false, ""
}

func detectSingleJA4MultiSNI(f Feature) (bool, string) {
	ja4 := FlattenPairs(f["ja4_top"])
	sni := FlattenPairs(f["sni_top"])
	if len(ja4) == 1 && len(sni) >= 10 && SafeInt(f["tls_clienthello_count"]) > 10 {
		return true, fmt.Sprintf("single JA4 %s shared by %d SNI names", ja4[0].Key, len(sni))
	}
	return false, ""
}

func detectBlock1344NordVPN(f Feature) (bool, string) {
	ratio := SafeFloat(f["block_1344_ratio"])
	malformed := SafeInt(f["malformed_count"])
	udp53Large := SafeInt(f["udp53_large_count"])
	if ratio >= 0.45 && (malformed > 0 || udp53Large > 0) {
		return true, fmt.Sprintf("NordVPN-like block_1344_ratio=%.2f malformed=%d udp53_large=%d", ratio, malformed, udp53Large)
	}
	return false, ""
}

func detectWizVPN1452(f Feature) (bool, string) {
	if SafeFloat(f["block_1452_ratio"]) < 0.50 {
		return false, ""
	}
	for _, d := range AllDomains(f) {
		if strings.Contains(d, "wizvpn") {
			return true, fmt.Sprintf("wizvpn domain with block_1452_ratio=%.2f", SafeFloat(f["block_1452_ratio"]))
		}
	}
	return false, ""
}

func detectMDNSHola(f Feature) (bool, string) {
	for _, p := range FlattenPairs(f["dns_top"]) {
		if strings.Contains(strings.ToLower(p.Key), "__hola__") {
			return true, fmt.Sprintf("mDNS exposes Hola marker %s", p.Key)
		}
	}
	return false, ""
}

func detectRandomLocalDomainsRule(f Feature) (bool, string) {
	count := DetectRandomLocalDomains(FlattenPairs(f["dns_top"]))
	if count >= 5 {
		return true, fmt.Sprintf("random .local domains count=%d", count)
	}
	return false, ""
}

func detectWPADStorm(f Feature) (bool, string) {
	wpad := SafeInt(f["wpad_query_count"])
	if wpad > 500 {
		return true, fmt.Sprintf("WPAD query storm count=%d", wpad)
	}
	return false, ""
}

func detectCheapTLDConcentration(f Feature) (bool, string) {
	domains := AllDomains(f)
	count := CountUniqueTLDs(domains, RiskTLDs)
	if count >= 3 {
		return true, fmt.Sprintf("high-risk TLD concentration unique_tlds=%d", count)
	}
	return false, ""
}

func detectDNSGapTCPReachable(f Feature) (bool, string) {
	dns := FlattenPairs(f["dns_top"])
	sni := FlattenPairs(f["sni_top"])
	dnsCount, sniCount := 0, 0
	all := map[string]bool{}
	for _, p := range dns {
		dnsCount += p.Count
		all[strings.ToLower(p.Key)] = true
	}
	for _, p := range sni {
		sniCount += p.Count
		all[strings.ToLower(p.Key)] = true
	}
	tlsCount := SafeInt(f["tls_clienthello_count"])
	if dnsCount < 5 && sniCount > 10 && tlsCount > 0 {
		return true, fmt.Sprintf("SNI requests=%d with DNS queries=%d", sniCount, dnsCount)
	}
	highEntropy := []string{}
	for d := range all {
		label := strings.Split(d, ".")[0]
		if strings.Contains(label, "-") {
			continue
		}
		if DomainEntropy(d) >= 3.5 {
			highEntropy = append(highEntropy, d)
		}
	}
	sort.Strings(highEntropy)
	if len(highEntropy) > 0 && tlsCount > 0 && dnsCount < 3 {
		return true, "high-entropy SNI/domain with missing DNS: " + strings.Join(firstN(highEntropy, 3), ", ")
	}
	return false, ""
}

func detectUDP53Masquerade(f Feature) (bool, string) {
	udp53Large := SafeInt(f["udp53_large_count"])
	malformed := SafeInt(f["malformed_count"])
	bestBlock, _ := MaxBlockRatio(f)
	if udp53Large > 10 && (bestBlock == 1344 || malformed > 0) {
		return true, fmt.Sprintf("UDP 53 masquerade udp53_large=%d malformed=%d best_block=%d", udp53Large, malformed, bestBlock)
	}
	return false, ""
}

func detectNordVPNDNSTunnel(f Feature) (bool, string) {
	udp53Count := SafeInt(f["udp53_count"])
	udp53Large := SafeInt(f["udp53_large_count"])
	malformed := SafeInt(f["malformed_count"])
	totalPackets := maxInt(1, SafeInt(f["total_packets"]))
	dominantRatio := SafeFloat(f["dominant_payload_ratio"])
	udp53Ratio := float64(udp53Count) / float64(totalPackets)
	if udp53Ratio < 0.80 || udp53Count == 0 {
		return false, ""
	}
	if float64(malformed) < float64(udp53Count)*0.95 {
		return false, ""
	}
	if float64(udp53Large) < float64(udp53Count)*0.50 {
		return false, ""
	}
	if dominantRatio < 0.40 {
		return false, ""
	}
	return true, fmt.Sprintf("NordVPN DNS tunnel udp53_ratio=%.2f malformed=%d udp53_large=%d", udp53Ratio, malformed, udp53Large)
}

func detectDOHPresent(f Feature) (bool, string) {
	doh := map[string]bool{"doh.pub": true, "dns.alidns.com": true, "dns.google": true, "cloudflare-dns.com": true, "mozilla.cloudflare-dns.com": true}
	hits := []string{}
	for _, p := range FlattenPairs(f["sni_top"]) {
		if doh[strings.ToLower(p.Key)] {
			hits = append(hits, p.Key)
		}
	}
	if len(hits) > 0 {
		return true, "DoH SNI present: " + strings.Join(hits, ", ")
	}
	return false, ""
}

func detectTwoPhaseConnection(f Feature) (bool, string) {
	ports := GetPorts(f)
	if ports[65311] > 0 && ports[5608] > 0 {
		return true, "two-phase connection ports 65311 + 5608"
	}
	return false, ""
}

func detectQUICTLSDual(f Feature) (bool, string) {
	quic := SafeInt(f["quic_frame_count"])
	tls := SafeInt(f["tls_clienthello_count"])
	if quic > 10 && tls > 5 {
		return true, fmt.Sprintf("QUIC + TLS dual protocol quic=%d tls=%d", quic, tls)
	}
	return false, ""
}

func detectExtremeFlowDominance(f Feature) (bool, string) {
	single := SafeFloat(f["single_flow_dominance"])
	duration := SafeFloat(f["max_flow_duration"])
	flows := SafeInt(f["flow_count"])
	if single >= 0.98 && duration > 60 && flows < 10 {
		return true, fmt.Sprintf("extreme single-flow dominance %.2f duration=%.0fs flows=%d", single, duration, flows)
	}
	return false, ""
}

type ComboScorer struct{}

func (ComboScorer) Score(f Feature) (ComboScores, []string) {
	s := ComboScores{}
	evidence := []string{}
	tlsCount := SafeInt(f["tls_clienthello_count"])
	nonstandardTLS := SafeInt(f["nonstandard_tls_flow_count"])
	alpnMissing := SafeFloat(f["alpn_missing_ratio"])
	topEndpointRatio := SafeFloat(f["top_endpoint_ratio"])

	if nonstandardTLS >= 5 && alpnMissing >= 0.90 && topEndpointRatio >= 0.70 {
		s.TLSSpoof += 3
		evidence = append(evidence, fmt.Sprintf("TLS tunnel shape nonstandard_tls=%d alpn_missing=%.2f endpoint_ratio=%.2f", nonstandardTLS, alpnMissing, topEndpointRatio))
	}
	if tlsCount > 0 && topEndpointRatio >= 0.80 {
		s.TLSSpoof++
		evidence = append(evidence, fmt.Sprintf("single endpoint carries TLS ratio=%.2f", topEndpointRatio))
	}

	noTLSLarge := SafeInt(f["no_tls_large_flow_count"])
	bestBlock, bestRatio := MaxBlockRatio(f)
	if noTLSLarge > 0 {
		s.RawEncrypted += 2
		evidence = append(evidence, fmt.Sprintf("large no-TLS TCP flows=%d", noTLSLarge))
	}
	if bestRatio >= 0.30 && containsInt([]int{1300, 1370, 1400, 1452, 1310, 1344, 1428, 1378}, bestBlock) {
		pts := minInt(3, int(bestRatio/0.15))
		s.RawEncrypted += pts
		evidence = append(evidence, fmt.Sprintf("fixed block feature block_%d_ratio=%.2f", bestBlock, bestRatio))
	} else if bestBlock == 1448 && bestRatio >= 0.80 {
		s.RawEncrypted += 2
		evidence = append(evidence, fmt.Sprintf("high TLS MTU fill block_1448_ratio=%.2f", bestRatio))
	}
	ports := GetPorts(f)
	for p := range ports {
		if SpecialPorts[p] {
			s.RawEncrypted += 2
			evidence = append(evidence, "special/nonstandard VPN port present")
			break
		}
	}

	singleFlow := SafeFloat(f["single_flow_dominance"])
	maxDuration := SafeFloat(f["max_flow_duration"])
	if topEndpointRatio >= 0.70 {
		s.EndpointBehavior += 2
		evidence = append(evidence, fmt.Sprintf("single endpoint concentration %.2f", topEndpointRatio))
	}
	if singleFlow >= 0.95 {
		s.EndpointBehavior += 2
		evidence = append(evidence, fmt.Sprintf("single-flow dominance %.2f", singleFlow))
	} else if singleFlow >= 0.90 {
		s.EndpointBehavior++
		evidence = append(evidence, fmt.Sprintf("dominant flow %.2f", singleFlow))
	}
	if maxDuration >= 3600 {
		s.EndpointBehavior += 2
		evidence = append(evidence, fmt.Sprintf("very long connection %.1fs", maxDuration))
	} else if maxDuration >= 600 {
		s.EndpointBehavior++
		evidence = append(evidence, fmt.Sprintf("long connection %.1fs", maxDuration))
	}

	domains := AllDomains(f)
	if hits := DomainKeywordHits(domains); len(hits) > 0 {
		s.DNSSNIAnomaly += 3
		evidence = append(evidence, "VPN domain keywords: "+strings.Join(firstN(hits, 5), ", "))
	}
	if tlds := CountUniqueTLDs(domains, RiskTLDs); tlds >= 3 {
		s.DNSSNIAnomaly += 3
		evidence = append(evidence, fmt.Sprintf("high-risk TLD count=%d", tlds))
	} else if SafeInt(f["risk_tld_count"]) >= 3 {
		s.DNSSNIAnomaly++
		evidence = append(evidence, fmt.Sprintf("risk_tld_count=%d", SafeInt(f["risk_tld_count"])))
	}
	if local := DetectRandomLocalDomains(FlattenPairs(f["dns_top"])); local >= 3 {
		s.DNSSNIAnomaly += 2
		evidence = append(evidence, fmt.Sprintf("random .local domains=%d", local))
	}

	ja4s := FlattenPairs(f["ja4_top"])
	if tlsCount > 0 && alpnMissing >= 0.80 {
		for _, ja4 := range ja4s {
			if ChromeJA4Prefix.MatchString(ja4.Key) {
				s.JA4Fingerprint += 3
				evidence = append(evidence, fmt.Sprintf("Chrome-like JA4 without ALPN %.2f", alpnMissing))
				break
			}
		}
	}
	if alpnMissing >= 0.80 {
		for _, ja4 := range ja4s {
			cc, ok := ExtractJA4CipherCount(ja4.Key)
			if (ok && (cc >= 19 || cc <= 6)) || JA4GoPattern.MatchString(ja4.Key) {
				s.JA4Fingerprint += 2
				evidence = append(evidence, "non-browser JA4 without ALPN")
				break
			}
		}
	}
	if SafeInt(f["cipher_suite_unique_count"]) == 1 && ToString(f["single_cipher_suite"]) != "" && tlsCount > 3 {
		s.JA4Fingerprint += 2
		evidence = append(evidence, "single cipher suite")
	}
	if alpnMissing >= 0.80 {
		for _, ja4 := range ja4s {
			if JA4GoPattern.MatchString(ja4.Key) {
				s.JA4Fingerprint++
				evidence = append(evidence, "Go TLS JA4 without ALPN")
				break
			}
		}
	}
	for _, ja4 := range ja4s {
		if TLS10JA4.MatchString(ja4.Key) {
			s.JA4Fingerprint += 2
			evidence = append(evidence, "TLS 1.0 JA4")
			break
		}
	}

	prot := ProtocolText(f)
	if ports[3306] > 0 && !strings.Contains(prot, "mysql") {
		s.PortProtocol += 2
		evidence = append(evidence, "TCP 3306 without MySQL")
	}
	if ports[65311] > 0 && ports[5608] > 0 {
		s.PortProtocol += 2
		evidence = append(evidence, "two-phase ports 65311 + 5608")
	}
	if ports[22225] > 0 || ports[22226] > 0 {
		s.PortProtocol += 2
		evidence = append(evidence, "Hola P2P ports")
	}

	return s, evidence
}

func InferVPNFamily(f Feature, evidenceText string) string {
	text := strings.ToLower(strings.Join(AllDomains(f), " ") + " " + ProtocolText(f) + " " + evidenceText)
	ports := GetPorts(f)
	bestBlock, bestRatio := MaxBlockRatio(f)
	signals := map[string]bool{}

	if strings.Contains(text, "isakmp") || strings.Contains(text, "ike") || strings.Contains(text, "esp") {
		signals["isakmp"], signals["ike"], signals["esp"] = true, true, true
	}
	if SafeBool(f["esp_in_udp_like"]) || SafeInt(f["udp4500_count"]) > 100 {
		signals["esp"] = true
	}
	if strings.Contains(text, "wg") || ports[51820] > 0 {
		signals["wg"], signals["wireguard"] = true, true
	}
	if strings.Contains(text, "openvpn") || ports[1194] > 0 || ports[1195] > 0 {
		signals["openvpn"] = true
	}
	if ports[1194] > 0 {
		signals["1194_port"] = true
	}

	addTextSignal := func(keys ...string) {
		for _, key := range keys {
			if strings.Contains(text, key) {
				signals[key] = true
			}
		}
	}
	addTextSignal("gosttwo", "shdowsocks", "nodesni", "kunlun04dns", "sdv2-", "hola", "zagent", "nord", "securepaidvpn", "securepaid", "clashverge", "ahahub", "ahapivot", "hubdhl", "hubups", "skylinevpn", "skylinenode", "wizvpn", "kuaifan", "wifiin.cn", "ultrasurf", "strongvpn")
	if signals["securepaid"] {
		signals["securepaidvpn"] = true
	}

	if ports[22225] > 0 || ports[22226] > 0 {
		signals["22225_port"] = true
	}
	if ports[11581] > 0 || ports[11582] > 0 || ports[11681] > 0 {
		signals["11581_port"], signals["11582_port"] = true, true
	}
	if ports[3128] > 0 {
		signals["3128_port"] = true
	}
	if bestBlock == 1428 && bestRatio >= 0.30 {
		signals["1428_block"] = true
	}
	if ports[3306] > 0 {
		signals["3306_port"] = true
	}
	if ports[5608] > 0 {
		signals["5608_port"] = true
	}
	if ports[65311] > 0 {
		signals["65311_port"] = true
	}
	if bestBlock == 1378 && bestRatio >= 0.60 {
		signals["1378_block"] = true
	}
	for _, n := range BlockSizes {
		if SafeFloat(f[fmt.Sprintf("block_%d_ratio", n)]) >= 0.30 {
			signals[fmt.Sprintf("%d_block", n)] = true
		}
	}
	if bestBlock == 1370 && bestRatio >= 0.30 {
		if SafeInt(f["nonstandard_tls_flow_count"]) > 0 || (SafeInt(f["tls_clienthello_count"]) > 0 && SafeFloat(f["alpn_missing_ratio"]) >= 0.80) {
			signals["1370_block_tls"] = true
		} else {
			signals["1370_block_no_tls"] = true
		}
	}
	for _, sni := range FlattenPairs(f["sni_top"]) {
		for _, enterprise := range FamousEnterpriseSNI {
			if strings.Contains(strings.ToLower(sni.Key), enterprise) {
				signals["sni_ip_mismatch"] = true
			}
		}
	}
	if SafeInt(f["udp53_large_count"]) > 10 && (bestBlock == 1344 || SafeInt(f["malformed_count"]) > 0) {
		signals["udp53_masquerade"] = true
	}

	type familyRule struct {
		required []string
		minHits  int
		family   string
	}
	rules := []familyRule{
		{[]string{"isakmp", "ike", "esp"}, 3, "IPsec/CyberGhost"},
		{[]string{"sni_ip_mismatch"}, 1, "JiguangVPN"},
		{[]string{"wg", "wireguard"}, 2, "WireGuard/NordVPN/StrongVPN"},
		{[]string{"openvpn"}, 1, "OpenVPN"},
		{[]string{"gosttwo", "shdowsocks"}, 2, "GOST"},
		{[]string{"nodesni", "kunlun04dns", "sdv2-", "1448_block", "5608_port", "65311_port"}, 2, "ShandianVPN"},
		{[]string{"wizvpn"}, 1, "WizVPN"},
		{[]string{"hola", "zagent", "22225_port", "1452_block"}, 2, "HolaVPN"},
		{[]string{"1378_block"}, 1, "CyberGhost/IPsec"},
		{[]string{"nord", "udp53_masquerade", "1344_block"}, 1, "NordVPN"},
		{[]string{"securepaidvpn", "3128_port"}, 2, "SecurePaidVPN"},
		{[]string{"1300_block"}, 1, "ShadowsocksR/SSR"},
		{[]string{"1370_block_tls"}, 1, "VLess"},
		{[]string{"1370_block_no_tls"}, 1, "VMess"},
		{[]string{"clashverge"}, 1, "Clash"},
		{[]string{"ahahub", "ahapivot", "hubdhl", "hubups", "1428_block"}, 2, "AhaVPN"},
		{[]string{"skylinevpn", "skylinenode", "11581_port", "11582_port", "1400_block"}, 2, "TianxingVPN"},
		{[]string{"1400_block"}, 1, "JiguangVPN/TianxingVPN"},
		{[]string{"kuaifan", "wifiin.cn"}, 1, "KuaifanVPN"},
		{[]string{"ultrasurf"}, 1, "UltraSurf"},
		{[]string{"strongvpn"}, 1, "StrongVPN"},
	}
	for _, r := range rules {
		hits := 0
		for _, req := range r.required {
			if signals[req] {
				hits++
			}
		}
		if hits >= r.minHits {
			return r.family
		}
	}
	for _, p := range []struct {
		signal string
		family string
	}{{"1310_block", "GOST"}, {"1344_block", "NordVPN"}, {"1378_block", "CyberGhost/IPsec"}, {"1428_block", "AhaVPN"}} {
		if signals[p.signal] {
			return p.family
		}
	}
	return "unknown_vpn"
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func containsInt(values []int, needle int) bool {
	for _, v := range values {
		if v == needle {
			return true
		}
	}
	return false
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

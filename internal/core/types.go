package core

type Feature map[string]any

type Pair struct {
	Key   string
	Count int
}

type RuleDef struct {
	ID          string
	Category    string
	Description string
	Confidence  int
	Detect      func(Feature) (bool, string)
	Enabled     bool
}

type RuleMatch struct {
	RuleID     string `json:"rule_id"`
	Category   string `json:"category"`
	Confidence int    `json:"confidence"`
	Evidence   string `json:"evidence"`
}

type ComboScores struct {
	TLSSpoof         int `json:"tls_spoof"`
	RawEncrypted     int `json:"raw_encrypted"`
	EndpointBehavior int `json:"endpoint_behavior"`
	DNSSNIAnomaly    int `json:"dns_sni_anomaly"`
	JA4Fingerprint   int `json:"ja4_fingerprint"`
	PortProtocol     int `json:"port_protocol"`
}

func (s ComboScores) Total() int {
	return s.TLSSpoof + s.RawEncrypted + s.EndpointBehavior + s.DNSSNIAnomaly + s.JA4Fingerprint + s.PortProtocol
}

func (s ComboScores) Map() map[string]int {
	return map[string]int{
		"tls_spoof":         s.TLSSpoof,
		"raw_encrypted":     s.RawEncrypted,
		"endpoint_behavior": s.EndpointBehavior,
		"dns_sni_anomaly":   s.DNSSNIAnomaly,
		"ja4_fingerprint":   s.JA4Fingerprint,
		"port_protocol":     s.PortProtocol,
	}
}

type DetectionResult struct {
	SourceArchive       string         `json:"source_archive"`
	PcapMember          string         `json:"pcap_member"`
	FileName            string         `json:"file_name"`
	SampleID            string         `json:"sample_id,omitempty"`
	CaptureID           string         `json:"capture_id,omitempty"`
	SplitGroup          string         `json:"split_group,omitempty"`
	Verdict             string         `json:"verdict"`
	VPNFamily           string         `json:"vpn_family"`
	Confidence          int            `json:"confidence"`
	RiskScore           float64        `json:"risk_score"`
	MatchedRules        []string       `json:"matched_rules"`
	ComboScore          *int           `json:"combo_score"`
	ComboDetail         map[string]int `json:"combo_detail"`
	Evidence            []string       `json:"evidence"`
	TopEndpoint         string         `json:"top_endpoint"`
	TopEndpointRatio    float64        `json:"top_endpoint_ratio"`
	TopSNI              any            `json:"top_sni"`
	TopDNS              any            `json:"top_dns"`
	DominantPayloadSize int            `json:"dominant_payload_size"`
	DominantPayloadRate float64        `json:"dominant_payload_ratio"`
	BestBlock           int            `json:"best_block"`
	BestBlockRatio      float64        `json:"best_block_ratio"`
	Notes               string         `json:"notes"`
}

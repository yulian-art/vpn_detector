package extract

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vpn_detector/internal/core"
)

type flowAgg struct {
	FlowID              string
	LocalIP             string
	LocalPort           int
	RemoteIP            string
	RemotePort          int
	Proto               string
	StartTS             float64
	EndTS               float64
	HasStart            bool
	PacketCount         int
	ByteCount           int
	OutBytes            int
	InBytes             int
	PayloadCounter      map[int]int
	DataPayloadCounter  map[int]int
	Protocols           map[string]int
	SNI                 map[string]int
	DNS                 map[string]int
	JA3                 map[string]int
	JA4                 map[string]int
	ALPNPresent         bool
	TLSHandshakeCount   int
	TLSClientHelloCount int
	TCPRSTCount         int
	TCPSYNCount         int
	IATCount            int
	IATUnder1ms         int
	LastTS              float64
	HasLast             bool
}

func newFlowAgg(flowID, localIP string, localPort int, remoteIP string, remotePort int, proto string) *flowAgg {
	return &flowAgg{
		FlowID:             flowID,
		LocalIP:            localIP,
		LocalPort:          localPort,
		RemoteIP:           remoteIP,
		RemotePort:         remotePort,
		Proto:              proto,
		PayloadCounter:     map[int]int{},
		DataPayloadCounter: map[int]int{},
		Protocols:          map[string]int{},
		SNI:                map[string]int{},
		DNS:                map[string]int{},
		JA3:                map[string]int{},
		JA4:                map[string]int{},
	}
}

func BuildTsharkFields(available map[string]bool) []string {
	base := []string{
		"frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
		"ip.proto", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
		"tcp.len", "udp.length", "tcp.flags", "_ws.col.Protocol", "_ws.col.Info",
		"tls.handshake.type", "tls.handshake.extensions_server_name",
		"tls.handshake.extensions_alpn_str", "tls.handshake.ciphersuite",
		"tls.handshake.version", "dns.qry.name", "dns.flags.rcode",
		"_ws.malformed", "malformed",
		"tls.handshake.ja3", "tls.handshake.ja4", "quic.version",
	}
	out := []string{}
	seen := map[string]bool{}
	for _, field := range base {
		if strings.HasPrefix(field, "_ws.") || len(available) == 0 || available[field] {
			if !seen[field] {
				seen[field] = true
				out = append(out, field)
			}
		}
	}
	return out
}

func TsharkRows(pcapPath string, fields []string, timeoutSec int) ([]map[string]string, error) {
	args := []string{"-r", pcapPath, "-T", "fields", "-E", "header=y", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	out, err := RunCommand(timeoutSec, "tshark", args...)
	if err != nil {
		return nil, err
	}
	return ReadTSV(out)
}

func ExtractFeaturesForPCAP(pcapPath, sourceArchive, memberName string, available map[string]bool, timeoutSec, maxFlows int) (map[string]any, error) {
	fields := BuildTsharkFields(available)
	rows, err := TsharkRows(pcapPath, fields, timeoutSec)
	if err != nil {
		return nil, err
	}

	flows := map[string]*flowAgg{}
	ipProtoCounts := map[string]int{}
	protocolCounts := map[string]int{}
	portCounts := map[int]int{}
	sniCounter := map[string]int{}
	dnsCounter := map[string]int{}
	ja3Counter := map[string]int{}
	ja4Counter := map[string]int{}
	endpointBytes := map[string]int{}
	payloadCounter := map[int]int{}
	dataPayloadCounter := map[int]int{}
	cipherSuiteCounter := map[string]int{}
	sshSynTimestamps := []float64{}

	info, _ := os.Stat(pcapPath)
	fileSize := int64(0)
	if info != nil {
		fileSize = info.Size()
	}
	summary := map[string]any{
		"source_archive":  sourceArchive,
		"pcap_member":     memberName,
		"file_name":       filepath.Base(filepath.FromSlash(memberName)),
		"file_size_bytes": fileSize,
	}
	totalPackets, tcpPackets, udpPackets := 0, 0, 0
	tlsClientHelloCount, tlsALPNPresentCount, tlsALPNMissingCount := 0, 0, 0
	udp500Count, udp4500Count, udp53Count, udp53LargeCount, malformedCount := 0, 0, 0, 0, 0
	totalPayloadBytes := 0
	quicFrameCount, randomLocalDomainCount, wpadQueryCount := 0, 0, 0

	for _, row := range rows {
		totalPackets++
		ipSrc := firstNonEmpty(row["ip.src"], row["ipv6.src"])
		ipDst := firstNonEmpty(row["ip.dst"], row["ipv6.dst"])
		if ipSrc == "" || ipDst == "" {
			continue
		}
		ipProto := strings.TrimSpace(row["ip.proto"])
		if ipProto != "" {
			ipProtoCounts[ipProto]++
		}
		protoCol := strings.TrimSpace(row["_ws.col.Protocol"])
		if protoCol != "" {
			protocolCounts[protoCol]++
		}
		tcpSport, tcpDport := core.SafeInt(row["tcp.srcport"]), core.SafeInt(row["tcp.dstport"])
		udpSport, udpDport := core.SafeInt(row["udp.srcport"]), core.SafeInt(row["udp.dstport"])
		proto := "OTHER"
		srcPort, dstPort, payloadLen := 0, 0, 0
		if tcpSport != 0 || tcpDport != 0 {
			proto = "TCP"
			srcPort, dstPort = tcpSport, tcpDport
			payloadLen = core.SafeInt(row["tcp.len"])
			tcpPackets++
		} else if udpSport != 0 || udpDport != 0 {
			proto = "UDP"
			srcPort, dstPort = udpSport, udpDport
			udpLen := core.SafeInt(row["udp.length"])
			if udpLen > 8 {
				payloadLen = udpLen - 8
			}
			udpPackets++
		} else if ipProto != "" {
			proto = "IPPROTO_" + ipProto
		}
		if srcPort != 0 {
			portCounts[srcPort]++
		}
		if dstPort != 0 {
			portCounts[dstPort]++
		}
		if proto == "UDP" && (srcPort == 500 || dstPort == 500) {
			udp500Count++
		}
		if proto == "UDP" && (srcPort == 4500 || dstPort == 4500) {
			udp4500Count++
		}
		if proto == "UDP" && (srcPort == 53 || dstPort == 53) {
			udp53Count++
			if payloadLen > 512 {
				udp53LargeCount++
			}
		}
		if row["_ws.malformed"] != "" || row["malformed"] != "" {
			malformedCount++
		}
		totalPayloadBytes += payloadLen
		if payloadLen > 0 {
			payloadCounter[payloadLen]++
		}
		if payloadLen > 100 {
			dataPayloadCounter[payloadLen]++
		}
		if strings.TrimSpace(row["quic.version"]) != "" {
			quicFrameCount++
		}
		tcpFlags := core.SafeInt(row["tcp.flags"])
		ts := core.SafeFloat(row["frame.time_epoch"])
		if proto == "TCP" && tcpFlags&0x02 != 0 && (srcPort == 22 || dstPort == 22) && ts > 0 {
			sshSynTimestamps = append(sshSynTimestamps, ts)
		}
		dnsQry := strings.ToLower(strings.TrimSpace(row["dns.qry.name"]))
		if dnsQry != "" {
			if strings.HasSuffix(dnsQry, ".local") {
				label := strings.Split(dnsQry, ".")[0]
				if len(label) >= 8 && core.EntropyLabel(label) >= 3.0 {
					randomLocalDomainCount++
				}
			}
			if dnsQry == "wpad" || strings.HasPrefix(dnsQry, "wpad.") {
				wpadQueryCount++
			}
		}

		localIP, localPort, remoteIP, remotePort, protoNorm := NormalizeFlow(ipSrc, srcPort, ipDst, dstPort, proto)
		direction := InferDirection(ipSrc, ipDst, localIP)
		endpoint := fmt.Sprintf("%s:%d/%s", remoteIP, remotePort, protoNorm)
		endpointBytes[endpoint] += payloadLen
		flowKey := fmt.Sprintf("%s|%d|%s|%d|%s", localIP, localPort, remoteIP, remotePort, protoNorm)
		flow := flows[flowKey]
		if flow == nil {
			flow = newFlowAgg(shortMD5(flowKey), localIP, localPort, remoteIP, remotePort, protoNorm)
			flows[flowKey] = flow
		}
		if ts > 0 {
			if !flow.HasStart {
				flow.StartTS = ts
				flow.HasStart = true
			}
			flow.EndTS = ts
			if flow.HasLast {
				dt := ts - flow.LastTS
				if dt >= 0 {
					flow.IATCount++
					if dt < 0.001 {
						flow.IATUnder1ms++
					}
				}
			}
			flow.LastTS = ts
			flow.HasLast = true
		}
		flow.PacketCount++
		flow.ByteCount += payloadLen
		if direction == "outbound" {
			flow.OutBytes += payloadLen
		} else if direction == "inbound" {
			flow.InBytes += payloadLen
		}
		if payloadLen > 0 {
			flow.PayloadCounter[payloadLen]++
		}
		if payloadLen > 100 {
			flow.DataPayloadCounter[payloadLen]++
		}
		if protoCol != "" {
			flow.Protocols[protoCol]++
		}
		sni := strings.TrimSpace(row["tls.handshake.extensions_server_name"])
		if sni != "" {
			flow.SNI[sni]++
			sniCounter[sni]++
		}
		dns := strings.TrimSpace(row["dns.qry.name"])
		if dns != "" {
			flow.DNS[dns]++
			dnsCounter[dns]++
		}
		ja3 := strings.TrimSpace(row["tls.handshake.ja3"])
		if ja3 != "" {
			flow.JA3[ja3]++
			ja3Counter[ja3]++
		}
		ja4 := strings.TrimSpace(row["tls.handshake.ja4"])
		if ja4 != "" {
			flow.JA4[ja4]++
			ja4Counter[ja4]++
		}
		hsType := strings.TrimSpace(row["tls.handshake.type"])
		if hsType != "" {
			flow.TLSHandshakeCount++
			if hsType == "1" || strings.HasPrefix(hsType, "1,") {
				flow.TLSClientHelloCount++
				tlsClientHelloCount++
				alpn := strings.TrimSpace(row["tls.handshake.extensions_alpn_str"])
				if alpn != "" {
					flow.ALPNPresent = true
					tlsALPNPresentCount++
				} else {
					tlsALPNMissingCount++
				}
				cs := strings.TrimSpace(row["tls.handshake.ciphersuite"])
				if cs != "" {
					cipherSuiteCounter[cs]++
				}
			}
			if hsType == "2" || strings.HasPrefix(hsType, "2,") {
				cs := strings.TrimSpace(row["tls.handshake.ciphersuite"])
				if cs != "" {
					cipherSuiteCounter[cs]++
				}
			}
		}
		if tcpFlags != 0 {
			if tcpFlags&0x04 != 0 {
				flow.TCPRSTCount++
			}
			if tcpFlags&0x02 != 0 {
				flow.TCPSYNCount++
			}
		}
	}

	finalFlows := make([]map[string]any, 0, len(flows))
	for _, f := range flows {
		finalFlows = append(finalFlows, finalizeFlow(f))
	}
	sort.Slice(finalFlows, func(i, j int) bool {
		return core.SafeInt(finalFlows[i]["byte_count"]) > core.SafeInt(finalFlows[j]["byte_count"])
	})

	nonstandardTLS, noTLSLarge, longFlowCount := 0, 0, 0
	maxMTUFill, maxIATUnder1ms := 0.0, 0.0
	maxSingleFlowBytes := 0
	totalFilePayload := maxInt(1, totalPayloadBytes)
	for _, flow := range finalFlows {
		if core.SafeFloat(flow["duration"]) > 60 {
			longFlowCount++
		}
		maxMTUFill = math.Max(maxMTUFill, core.SafeFloat(flow["mtu_fill_ratio"]))
		maxIATUnder1ms = math.Max(maxIATUnder1ms, core.SafeFloat(flow["iat_under_1ms_ratio"]))
		maxSingleFlowBytes = maxInt(maxSingleFlowBytes, core.SafeInt(flow["byte_count"]))
		if core.SafeBool(flow["has_tls_handshake"]) && !core.StandardTLSPorts[core.SafeInt(flow["remote_port"])] {
			nonstandardTLS++
		}
		if !core.SafeBool(flow["has_tls_handshake"]) && core.SafeInt(flow["byte_count"]) > 1024*1024 && core.ToString(flow["proto"]) == "TCP" {
			noTLSLarge++
		}
	}
	dataTotal := sumIntMap(dataPayloadCounter)
	fileBlockRatio := func(n int) float64 {
		if dataTotal <= 0 {
			return 0
		}
		hits := 0
		for length, count := range dataPayloadCounter {
			if length > 100 && length%n == 0 {
				hits += count
			}
		}
		return float64(hits) / float64(dataTotal)
	}
	dominantSize, dominantRatio := dominantPayload(payloadCounter)
	mtuHits := 0
	for length, count := range dataPayloadCounter {
		if length >= 1400 && length <= 1460 {
			mtuHits += count
		}
	}
	mtuFillRatio := 0.0
	if dataTotal > 0 {
		mtuFillRatio = float64(mtuHits) / float64(dataTotal)
	}
	topEndpoint, topEndpointBytes := topStringCounter(endpointBytes)
	topEndpointRatio := float64(topEndpointBytes) / float64(totalFilePayload)
	singleFlowDominance := float64(maxSingleFlowBytes) / float64(totalFilePayload)
	sshSynPeriodic := detectPeriodic(sshSynTimestamps)
	cipherUniqueCount := len(cipherSuiteCounter)
	singleCipher := ""
	if cipherUniqueCount == 1 && tlsClientHelloCount > 0 {
		for k := range cipherSuiteCounter {
			singleCipher = k
		}
	}
	udp4500 := analyzeUDP4500Payloads(pcapPath, timeoutSec)

	summary["total_packets"] = totalPackets
	summary["tcp_packets"] = tcpPackets
	summary["udp_packets"] = udpPackets
	summary["ip_proto_counts"] = ipProtoCounts
	summary["protocol_counts"] = protocolCounts
	summary["port_counts_top"] = core.TopIntPairs(portCounts, 30)
	summary["sni_top"] = core.TopMapPairs(sniCounter, 30)
	summary["dns_top"] = core.TopMapPairs(dnsCounter, 30)
	summary["ja3_top"] = core.TopMapPairs(ja3Counter, 10)
	summary["ja4_top"] = core.TopMapPairs(ja4Counter, 10)
	summary["tls_clienthello_count"] = tlsClientHelloCount
	summary["tls_alpn_present_count"] = tlsALPNPresentCount
	summary["tls_alpn_missing_count"] = tlsALPNMissingCount
	if tlsClientHelloCount > 0 {
		summary["alpn_missing_ratio"] = float64(tlsALPNMissingCount) / float64(tlsClientHelloCount)
	} else {
		summary["alpn_missing_ratio"] = 0.0
	}
	summary["nonstandard_tls_flow_count"] = nonstandardTLS
	summary["no_tls_large_flow_count"] = noTLSLarge
	summary["udp500_count"] = udp500Count
	summary["udp4500_count"] = udp4500Count
	summary["udp53_count"] = udp53Count
	summary["udp53_large_count"] = udp53LargeCount
	summary["malformed_count"] = malformedCount
	summary["total_payload_bytes"] = totalPayloadBytes
	summary["top_endpoint"] = topEndpoint
	summary["top_endpoint_ratio"] = topEndpointRatio
	summary["single_flow_dominance"] = singleFlowDominance
	summary["flow_count"] = len(finalFlows)
	summary["long_flow_count"] = longFlowCount
	summary["dominant_payload_size"] = dominantSize
	summary["dominant_payload_ratio"] = dominantRatio
	summary["mtu_fill_ratio"] = mtuFillRatio
	summary["max_flow_mtu_fill_ratio"] = maxMTUFill
	summary["max_flow_iat_under_1ms_ratio"] = maxIATUnder1ms
	summary["max_flow_duration"] = maxFlowDuration(finalFlows)
	summary["risk_tld_count"] = countRiskTLDs(sniCounter, dnsCounter)
	summary["max_domain_entropy"] = maxDomainEntropy(sniCounter, dnsCounter)
	summary["cipher_suite_unique_count"] = cipherUniqueCount
	summary["single_cipher_suite"] = singleCipher
	summary["quic_frame_count"] = quicFrameCount
	summary["ssh_syn_count"] = len(sshSynTimestamps)
	summary["ssh_syn_periodic"] = sshSynPeriodic
	summary["random_local_domain_count"] = randomLocalDomainCount
	summary["wpad_query_count"] = wpadQueryCount
	for _, n := range core.BlockSizes {
		summary[fmt.Sprintf("block_%d_ratio", n)] = fileBlockRatio(n)
	}
	for k, v := range udp4500 {
		summary[k] = v
	}
	for k, v := range SampleMetadata(sourceArchive, memberName, fileSize) {
		summary[k] = v
	}

	if maxFlows <= 0 || maxFlows > len(finalFlows) {
		maxFlows = len(finalFlows)
	}
	return map[string]any{
		"file_feature": summary,
		"top_flows":    finalFlows[:maxFlows],
	}, nil
}

func finalizeFlow(f *flowAgg) map[string]any {
	duration := 0.0
	if f.HasStart {
		duration = math.Max(0, f.EndTS-f.StartTS)
	}
	dataTotal := sumIntMap(f.DataPayloadCounter)
	payloadTotal := sumIntMap(f.PayloadCounter)
	ratioMod := func(n int) float64 {
		if dataTotal <= 0 {
			return 0
		}
		hits := 0
		for length, count := range f.DataPayloadCounter {
			if length > 100 && length%n == 0 {
				hits += count
			}
		}
		return float64(hits) / float64(dataTotal)
	}
	dominantSize, dominantRatio := dominantPayload(f.PayloadCounter)
	mtuHits := 0
	for length, count := range f.DataPayloadCounter {
		if length >= 1400 && length <= 1460 {
			mtuHits += count
		}
	}
	mtuFillRatio := 0.0
	if dataTotal > 0 {
		mtuFillRatio = float64(mtuHits) / float64(dataTotal)
	}
	var ulDLRatio any
	if f.InBytes > 0 {
		ulDLRatio = float64(f.OutBytes) / float64(f.InBytes)
	} else if f.OutBytes > 0 {
		ulDLRatio = math.Inf(1)
	} else {
		ulDLRatio = nil
	}
	row := map[string]any{
		"flow_id":                  f.FlowID,
		"local_ip":                 f.LocalIP,
		"local_port":               f.LocalPort,
		"remote_ip":                f.RemoteIP,
		"remote_port":              f.RemotePort,
		"proto":                    f.Proto,
		"start_ts":                 nil,
		"end_ts":                   nil,
		"duration":                 duration,
		"packet_count":             f.PacketCount,
		"byte_count":               f.ByteCount,
		"out_bytes":                f.OutBytes,
		"in_bytes":                 f.InBytes,
		"ul_dl_ratio":              ulDLRatio,
		"dominant_payload_size":    dominantSize,
		"dominant_payload_ratio":   dominantRatio,
		"mtu_fill_ratio":           mtuFillRatio,
		"iat_under_1ms_ratio":      ratioInts(f.IATUnder1ms, f.IATCount),
		"rst_ratio":                ratioInts(f.TCPRSTCount, f.PacketCount),
		"syn_count":                f.TCPSYNCount,
		"has_tls_handshake":        f.TLSHandshakeCount > 0,
		"tls_clienthello_count":    f.TLSClientHelloCount,
		"alpn_present":             f.ALPNPresent,
		"top_sni":                  core.TopMapPairs(f.SNI, 3),
		"top_dns":                  core.TopMapPairs(f.DNS, 3),
		"top_protocols":            core.TopMapPairs(f.Protocols, 5),
		"top_ja3":                  core.TopMapPairs(f.JA3, 3),
		"top_ja4":                  core.TopMapPairs(f.JA4, 3),
		"_payload_total_for_debug": payloadTotal,
	}
	if f.HasStart {
		row["start_ts"] = f.StartTS
		row["end_ts"] = f.EndTS
	}
	for _, n := range core.BlockSizes {
		row[fmt.Sprintf("block_%d_ratio", n)] = ratioMod(n)
	}
	delete(row, "_payload_total_for_debug")
	return row
}

func ExtractFeatures(inputs []string, outPath string, timeoutSec, maxFlows int) error {
	if err := RequireTshark(); err != nil {
		return err
	}
	available := GetAvailableFields(60)
	records := []any{}
	err := ForEachInputPCAP(inputs, func(sourceArchive, memberName, localPath string) error {
		rec, err := ExtractFeaturesForPCAP(localPath, sourceArchive, memberName, available, timeoutSec, maxFlows)
		if err != nil {
			rec = map[string]any{
				"file_feature": map[string]any{
					"source_archive": sourceArchive,
					"pcap_member":    memberName,
					"file_name":      filepath.Base(filepath.FromSlash(memberName)),
					"extract_error":  err.Error(),
				},
				"top_flows": []any{},
			}
		}
		records = append(records, rec)
		return nil
	})
	if err != nil {
		return err
	}
	return core.WriteJSONL(outPath, records)
}

func shortMD5(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func sumIntMap(m map[int]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}

func dominantPayload(counter map[int]int) (int, float64) {
	total := sumIntMap(counter)
	if total == 0 {
		return 0, 0
	}
	bestSize, bestCount := 0, 0
	for size, count := range counter {
		if count > bestCount || (count == bestCount && size < bestSize) {
			bestSize, bestCount = size, count
		}
	}
	return bestSize, float64(bestCount) / float64(total)
}

func topStringCounter(counter map[string]int) (string, int) {
	bestKey, bestVal := "", 0
	for k, v := range counter {
		if v > bestVal || (v == bestVal && k < bestKey) {
			bestKey, bestVal = k, v
		}
	}
	return bestKey, bestVal
}

func maxFlowDuration(flows []map[string]any) float64 {
	best := 0.0
	for _, f := range flows {
		best = math.Max(best, core.SafeFloat(f["duration"]))
	}
	return best
}

func countRiskTLDs(sni, dns map[string]int) int {
	count := 0
	for d := range sni {
		if hasRiskTLD(d) {
			count++
		}
	}
	for d := range dns {
		if hasRiskTLD(d) {
			count++
		}
	}
	return count
}

func hasRiskTLD(domain string) bool {
	d := strings.ToLower(domain)
	for _, tld := range core.RiskTLDs {
		if strings.HasSuffix(d, tld) {
			return true
		}
	}
	return false
}

func maxDomainEntropy(sni, dns map[string]int) float64 {
	best := 0.0
	for d := range sni {
		best = math.Max(best, core.DomainEntropy(d))
	}
	for d := range dns {
		best = math.Max(best, core.DomainEntropy(d))
	}
	return best
}

func ratioInts(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func detectPeriodic(timestamps []float64) bool {
	if len(timestamps) <= 20 {
		return false
	}
	sort.Float64s(timestamps)
	intervals := []float64{}
	for i := 1; i < len(timestamps); i++ {
		intervals = append(intervals, timestamps[i]-timestamps[i-1])
	}
	if len(intervals) == 0 {
		return false
	}
	mean := 0.0
	for _, v := range intervals {
		mean += v
	}
	mean /= float64(len(intervals))
	if mean <= 0 {
		return false
	}
	variance := 0.0
	for _, v := range intervals {
		d := v - mean
		variance += d * d
	}
	std := math.Sqrt(variance / float64(len(intervals)))
	return std/mean < 0.3 && mean > 2 && mean < 15
}

func analyzeUDP4500Payloads(pcapPath string, timeoutSec int) map[string]any {
	result := map[string]any{
		"udp4500_payload_checked":      0,
		"udp4500_non_esp_marker_count": 0,
		"udp4500_esp_like_count":       0,
		"udp4500_spi_top":              []any{},
		"esp_in_udp_like":              false,
	}
	args := []string{"-r", pcapPath, "-Y", "udp.port == 4500", "-T", "fields", "-E", "header=y", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f", "-e", "ip.src", "-e", "ip.dst", "-e", "udp.payload"}
	out, err := RunCommand(timeoutSec, "tshark", args...)
	if err != nil || strings.TrimSpace(out) == "" {
		return result
	}
	rows, err := ReadTSV(out)
	if err != nil {
		return result
	}
	spiCounter := map[string]int{}
	seqs := map[string][]int{}
	checked, nonESP := 0, 0
	for _, row := range rows {
		payload := strings.ReplaceAll(strings.ToLower(row["udp.payload"]), ":", "")
		if len(payload) < 8 {
			continue
		}
		checked++
		if strings.HasPrefix(payload, "00000000") {
			nonESP++
			continue
		}
		if len(payload) >= 16 {
			spi := payload[:8]
			seqHex := payload[8:16]
			var seq int
			if _, err := fmt.Sscanf(seqHex, "%x", &seq); err != nil {
				continue
			}
			key := row["ip.src"] + "|" + row["ip.dst"] + "|" + spi
			seqs[key] = append(seqs[key], seq)
			spiCounter[spi]++
		}
	}
	espLike := 0
	for _, values := range seqs {
		if len(values) < 5 {
			continue
		}
		inc, total := 0, 0
		prevSet := false
		prev := 0
		for _, seq := range values {
			if prevSet {
				total++
				if seq > prev {
					inc++
				}
			}
			prev = seq
			prevSet = true
		}
		if total > 0 && float64(inc)/float64(total) >= 0.6 {
			espLike += len(values)
		}
	}
	result["udp4500_payload_checked"] = checked
	result["udp4500_non_esp_marker_count"] = nonESP
	result["udp4500_esp_like_count"] = espLike
	result["udp4500_spi_top"] = core.TopMapPairs(spiCounter, 5)
	result["esp_in_udp_like"] = espLike >= 10
	return result
}

func DebugJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

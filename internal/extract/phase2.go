package extract

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"vpn_detector/internal/core"
)

type PacketRow map[string]any

func TsharkPacketRows(pcapPath string, timeoutSec int) ([]PacketRow, error) {
	fields := []string{
		"frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
		"ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport",
		"udp.srcport", "udp.dstport", "_ws.col.Protocol",
	}
	args := []string{"-r", pcapPath, "-T", "fields", "-E", "header=y", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"}
	for _, field := range fields {
		args = append(args, "-e", field)
	}
	out, err := RunCommand(timeoutSec, "tshark", args...)
	if err != nil {
		return nil, err
	}
	rawRows, err := ReadTSV(out)
	if err != nil {
		return nil, err
	}
	rows := make([]PacketRow, 0, len(rawRows))
	for _, raw := range rawRows {
		rows = append(rows, NormalizePacketRow(raw))
	}
	return rows, nil
}

func NormalizePacketRow(row map[string]string) PacketRow {
	srcPort := core.SafeInt(firstNonEmpty(row["tcp.srcport"], row["udp.srcport"]))
	dstPort := core.SafeInt(firstNonEmpty(row["tcp.dstport"], row["udp.dstport"]))
	transport := "OTHER"
	if row["tcp.srcport"] != "" || row["tcp.dstport"] != "" {
		transport = "TCP"
	} else if row["udp.srcport"] != "" || row["udp.dstport"] != "" {
		transport = "UDP"
	} else if row["_ws.col.Protocol"] != "" {
		transport = strings.ToUpper(row["_ws.col.Protocol"])
	}
	return PacketRow{
		"frame_number": core.SafeInt(row["frame.number"]),
		"timestamp":    core.SafeFloat(row["frame.time_epoch"]),
		"packet_len":   core.SafeInt(row["frame.len"]),
		"src_ip":       firstNonEmpty(row["ip.src"], row["ipv6.src"]),
		"dst_ip":       firstNonEmpty(row["ip.dst"], row["ipv6.dst"]),
		"src_port":     srcPort,
		"dst_port":     dstPort,
		"transport":    strings.ToUpper(transport),
	}
}

type FlowTuple struct {
	SrcIP     string
	SrcPort   int
	DstIP     string
	DstPort   int
	Transport string
}

func CanonicalFlowTuple(packet PacketRow) FlowTuple {
	src := core.ToString(packet["src_ip"])
	dst := core.ToString(packet["dst_ip"])
	srcPort := core.SafeInt(packet["src_port"])
	dstPort := core.SafeInt(packet["dst_port"])
	transport := strings.ToUpper(core.ToString(packet["transport"]))
	left := fmt.Sprintf("%s:%d", src, srcPort)
	right := fmt.Sprintf("%s:%d", dst, dstPort)
	if left <= right {
		return FlowTuple{src, srcPort, dst, dstPort, transport}
	}
	return FlowTuple{dst, dstPort, src, srcPort, transport}
}

func StableFlowID(sampleID string, ft FlowTuple) string {
	return core.StableID(sampleID, ft.SrcIP, ft.SrcPort, ft.DstIP, ft.DstPort, ft.Transport)[:20]
}

func PacketDirection(packet PacketRow, ft FlowTuple) int {
	if core.ToString(packet["src_ip"]) == ft.SrcIP && core.SafeInt(packet["src_port"]) == ft.SrcPort {
		return 1
	}
	return -1
}

func DirectionsForPackets(packets []PacketRow, ft FlowTuple, mode string) []int {
	canonical := make([]int, 0, len(packets))
	for _, p := range packets {
		canonical = append(canonical, PacketDirection(p, ft))
	}
	if mode == "canonical" || len(canonical) == 0 {
		return canonical
	}
	first := canonical[0]
	out := make([]int, 0, len(canonical))
	for _, sign := range canonical {
		if sign == first {
			out = append(out, 1)
		} else {
			out = append(out, -1)
		}
	}
	return out
}

func BuildFlowFeatures(packetRows []PacketRow, metadata map[string]any, directionMode string) []map[string]any {
	grouped := map[FlowTuple][]PacketRow{}
	for _, p := range packetRows {
		if core.ToString(p["src_ip"]) == "" || core.ToString(p["dst_ip"]) == "" {
			continue
		}
		ft := CanonicalFlowTuple(p)
		grouped[ft] = append(grouped[ft], p)
	}
	keys := make([]FlowTuple, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return tupleString(keys[i]) < tupleString(keys[j]) })
	rows := []map[string]any{}
	for _, ft := range keys {
		packets := grouped[ft]
		sortPackets(packets)
		timestamps := []float64{}
		lengths := []int{}
		for _, p := range packets {
			timestamps = append(timestamps, core.SafeFloat(p["timestamp"]))
			lengths = append(lengths, core.SafeInt(p["packet_len"]))
		}
		iats := []float64{}
		for i := 1; i < len(timestamps); i++ {
			iats = append(iats, math.Max(0, timestamps[i]-timestamps[i-1]))
		}
		directions := DirectionsForPackets(packets, ft, directionMode)
		upBytes, downBytes, upPackets, downPackets := 0, 0, 0, 0
		for i, length := range lengths {
			if i < len(directions) && directions[i] == 1 {
				upBytes += length
				upPackets++
			} else {
				downBytes += length
				downPackets++
			}
		}
		row := copyMap(metadata)
		row["flow_id"] = StableFlowID(core.ToString(metadata["sample_id"]), ft)
		row["src_ip"] = ft.SrcIP
		row["dst_ip"] = ft.DstIP
		row["src_port"] = ft.SrcPort
		row["dst_port"] = ft.DstPort
		row["transport"] = ft.Transport
		row["direction_mode"] = directionMode
		row["packet_count"] = len(packets)
		row["byte_count"] = sumInts(lengths)
		row["duration"] = duration(timestamps)
		row["iat_mean"] = meanFloat(iats)
		row["iat_std"] = stdFloat(iats)
		row["pkt_len_mean"] = meanInt(lengths)
		row["pkt_len_std"] = stdInt(lengths)
		row["up_packets"] = upPackets
		row["down_packets"] = downPackets
		row["up_bytes"] = upBytes
		row["down_bytes"] = downBytes
		row["up_down_byte_ratio"] = ratio(upBytes, downBytes)
		row["first_seen"] = firstTS(timestamps)
		row["last_seen"] = lastTS(timestamps)
		rows = append(rows, row)
	}
	return rows
}

func BuildSequenceFeatures(packetRows []PacketRow, metadata map[string]any, firstN int, directionMode string) ([]map[string]any, error) {
	if firstN != 32 && firstN != 64 {
		return nil, fmt.Errorf("first-n must be 32 or 64")
	}
	grouped := map[FlowTuple][]PacketRow{}
	for _, p := range packetRows {
		if core.ToString(p["src_ip"]) == "" || core.ToString(p["dst_ip"]) == "" {
			continue
		}
		ft := CanonicalFlowTuple(p)
		grouped[ft] = append(grouped[ft], p)
	}
	keys := make([]FlowTuple, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return tupleString(keys[i]) < tupleString(keys[j]) })
	rows := []map[string]any{}
	for _, ft := range keys {
		packets := grouped[ft]
		sortPackets(packets)
		if len(packets) > firstN {
			packets = packets[:firstN]
		}
		lengths := []int{}
		timestamps := []float64{}
		for _, p := range packets {
			lengths = append(lengths, core.SafeInt(p["packet_len"]))
			timestamps = append(timestamps, core.SafeFloat(p["timestamp"]))
		}
		directions := DirectionsForPackets(packets, ft, directionMode)
		signed := []int{}
		for i, length := range lengths {
			sign := 1
			if i < len(directions) {
				sign = directions[i]
			}
			signed = append(signed, length*sign)
		}
		iatMS := []float64{}
		prevSet := false
		prev := 0.0
		for _, ts := range timestamps {
			if !prevSet {
				iatMS = append(iatMS, 0)
			} else {
				iatMS = append(iatMS, math.Max(0, (ts-prev)*1000.0))
			}
			prev = ts
			prevSet = true
		}
		logIAT := []float64{}
		for _, v := range iatMS {
			logIAT = append(logIAT, math.Log1p(v))
		}
		row := copyMap(metadata)
		row["flow_id"] = StableFlowID(core.ToString(metadata["sample_id"]), ft)
		row["direction_mode"] = directionMode
		row["seq_len"] = len(packets)
		row["pkt_len_seq"] = lengths
		row["signed_len_seq"] = signed
		row["direction_seq"] = directions
		row["iat_ms_seq"] = iatMS
		row["log1p_iat_seq"] = logIAT
		rows = append(rows, row)
	}
	return rows, nil
}

func ExtractFlowFeatures(inputs []string, outPath string, timeoutSec int, directionMode string) error {
	if err := RequireTshark(); err != nil {
		return err
	}
	rows := []map[string]any{}
	err := ForEachInputPCAP(inputs, func(sourceArchive, memberName, localPath string) error {
		size := int64(0)
		if st, err := osStat(localPath); err == nil {
			size = st
		}
		meta := SampleMetadata(sourceArchive, memberName, size)
		packets, err := TsharkPacketRows(localPath, timeoutSec)
		if err != nil {
			return err
		}
		rows = append(rows, BuildFlowFeatures(packets, meta, directionMode)...)
		return nil
	})
	if err != nil {
		return err
	}
	return core.WriteCSV(outPath, rows, []string{"sample_id", "capture_id", "split_group", "source_archive", "pcap_member", "file_name", "flow_id"})
}

func ExtractSequenceFeatures(inputs []string, outPath string, firstN, timeoutSec int, directionMode string) error {
	if err := RequireTshark(); err != nil {
		return err
	}
	rows := []map[string]any{}
	err := ForEachInputPCAP(inputs, func(sourceArchive, memberName, localPath string) error {
		size := int64(0)
		if st, err := osStat(localPath); err == nil {
			size = st
		}
		meta := SampleMetadata(sourceArchive, memberName, size)
		packets, err := TsharkPacketRows(localPath, timeoutSec)
		if err != nil {
			return err
		}
		built, err := BuildSequenceFeatures(packets, meta, firstN, directionMode)
		if err != nil {
			return err
		}
		rows = append(rows, built...)
		return nil
	})
	if err != nil {
		return err
	}
	return core.WriteCSV(outPath, rows, []string{"sample_id", "capture_id", "split_group", "source_archive", "pcap_member", "file_name", "flow_id"})
}

func tupleString(ft FlowTuple) string {
	return fmt.Sprintf("%s|%d|%s|%d|%s", ft.SrcIP, ft.SrcPort, ft.DstIP, ft.DstPort, ft.Transport)
}

func sortPackets(packets []PacketRow) {
	sort.Slice(packets, func(i, j int) bool {
		ti, tj := core.SafeFloat(packets[i]["timestamp"]), core.SafeFloat(packets[j]["timestamp"])
		if ti == tj {
			return core.SafeInt(packets[i]["frame_number"]) < core.SafeInt(packets[j]["frame_number"])
		}
		return ti < tj
	})
}

func copyMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sumInts(values []int) int {
	total := 0
	for _, v := range values {
		total += v
	}
	return total
}

func meanInt(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	return float64(sumInts(values)) / float64(len(values))
}

func meanFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, v := range values {
		total += v
	}
	return total / float64(len(values))
}

func stdInt(values []int) float64 {
	floats := make([]float64, 0, len(values))
	for _, v := range values {
		floats = append(floats, float64(v))
	}
	return stdFloat(floats)
}

func stdFloat(values []float64) float64 {
	if len(values) <= 1 {
		return 0
	}
	m := meanFloat(values)
	variance := 0.0
	for _, v := range values {
		d := v - m
		variance += d * d
	}
	return math.Sqrt(variance / float64(len(values)))
}

func duration(timestamps []float64) float64 {
	if len(timestamps) == 0 {
		return 0
	}
	return math.Max(0, lastTS(timestamps)-firstTS(timestamps))
}

func firstTS(timestamps []float64) float64 {
	if len(timestamps) == 0 {
		return 0
	}
	return timestamps[0]
}

func lastTS(timestamps []float64) float64 {
	if len(timestamps) == 0 {
		return 0
	}
	return timestamps[len(timestamps)-1]
}

func ratio(up, down int) float64 {
	if down > 0 {
		return float64(up) / float64(down)
	}
	if up > 0 {
		return math.Inf(1)
	}
	return 0
}

func osStat(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

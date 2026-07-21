package extract

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vpn_detector/internal/core"
)

var PCAPExts = map[string]bool{".pcap": true, ".pcapng": true, ".cap": true}

func RequireTshark() error {
	if _, err := exec.LookPath("tshark"); err != nil {
		return fmt.Errorf("tshark not found; install Wireshark and add tshark to PATH")
	}
	return nil
}

func RunCommand(timeoutSec int, name string, args ...string) (string, error) {
	timeout := time.Duration(timeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("command timed out: %s %s", name, strings.Join(args, " "))
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("command failed: %s %s\nstderr: %s", name, strings.Join(args, " "), string(ee.Stderr))
		}
		return "", err
	}
	return string(out), nil
}

func GetAvailableFields(timeoutSec int) map[string]bool {
	out, err := RunCommand(timeoutSec, "tshark", "-G", "fields")
	if err != nil {
		return map[string]bool{}
	}
	fields := map[string]bool{"_ws.col.Protocol": true, "_ws.col.Info": true}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 && parts[0] == "F" {
			fields[parts[2]] = true
		}
	}
	return fields
}

func ForEachInputPCAP(inputs []string, fn func(sourceArchive, memberName, localPath string) error) error {
	for _, raw := range inputs {
		path := filepath.Clean(raw)
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			children := []string{}
			if err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				children = append(children, p)
				return nil
			}); err != nil {
				return err
			}
			sort.Strings(children)
			for _, child := range children {
				if err := handleInputFile(child, fn); err != nil {
					return err
				}
			}
			continue
		}
		if err := handleInputFile(path, fn); err != nil {
			return err
		}
	}
	return nil
}

func handleInputFile(path string, fn func(sourceArchive, memberName, localPath string) error) error {
	ext := strings.ToLower(filepath.Ext(path))
	if PCAPExts[ext] {
		return fn("", path, path)
	}
	if ext != ".zip" {
		return nil
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !PCAPExts[strings.ToLower(filepath.Ext(file.Name))] {
			continue
		}
		tmpdir, err := os.MkdirTemp("", "vpn-detector-zip-*")
		if err != nil {
			return err
		}
		local := filepath.Join(tmpdir, filepath.Base(file.Name))
		if err := extractZipMember(file, local); err != nil {
			os.RemoveAll(tmpdir)
			return err
		}
		err = fn(path, file.Name, local)
		os.RemoveAll(tmpdir)
		if err != nil {
			return err
		}
	}
	return nil
}

func extractZipMember(file *zip.File, local string) error {
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(local)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}

func ReadTSV(out string) ([]map[string]string, error) {
	if strings.TrimSpace(out) == "" {
		return []map[string]string{}, nil
	}
	r := csv.NewReader(strings.NewReader(out))
	r.Comma = '\t'
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	rows := []map[string]string{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		row := map[string]string{}
		for i, h := range header {
			if i < len(rec) {
				row[h] = rec[i]
			} else {
				row[h] = ""
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func IsPrivateIP(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

func NormalizeFlow(srcIP string, srcPort int, dstIP string, dstPort int, proto string) (localIP string, localPort int, remoteIP string, remotePort int, protoNorm string) {
	srcPrivate := IsPrivateIP(srcIP)
	dstPrivate := IsPrivateIP(dstIP)
	if srcPrivate && !dstPrivate {
		return srcIP, srcPort, dstIP, dstPort, proto
	}
	if dstPrivate && !srcPrivate {
		return dstIP, dstPort, srcIP, srcPort, proto
	}
	left := fmt.Sprintf("%s:%d", srcIP, srcPort)
	right := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if left <= right {
		return srcIP, srcPort, dstIP, dstPort, proto
	}
	return dstIP, dstPort, srcIP, srcPort, proto
}

func InferDirection(srcIP, dstIP, localIP string) string {
	if srcIP == localIP {
		return "outbound"
	}
	if dstIP == localIP {
		return "inbound"
	}
	return "unknown"
}

func SampleMetadata(sourceArchive, pcapMember string, fileSize any) map[string]any {
	fileName := filepath.Base(filepath.FromSlash(pcapMember))
	captureID := core.MakeCaptureID(sourceArchive, pcapMember, fileName)
	return map[string]any{
		"sample_id":      core.MakeSampleID(sourceArchive, pcapMember, fileName, fileSize),
		"capture_id":     captureID,
		"split_group":    core.MakeSplitGroup(sourceArchive, pcapMember, fileName, captureID),
		"source_archive": sourceArchive,
		"pcap_member":    pcapMember,
		"file_name":      fileName,
	}
}

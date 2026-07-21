package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func idText(v any) string {
	if v == nil {
		return ""
	}
	return strings.ReplaceAll(fmt.Sprint(v), "\\", "/")
}

func StableID(parts ...any) string {
	raw := make([]string, 0, len(parts))
	for _, part := range parts {
		raw = append(raw, idText(part))
	}
	sum := sha256.Sum256([]byte(strings.Join(raw, "|")))
	return hex.EncodeToString(sum[:])[:16]
}

func MakeSampleID(sourceArchive, pcapMember, fileName, fileSizeBytes any) string {
	return StableID(sourceArchive, pcapMember, fileName, fileSizeBytes)
}

func MakeCaptureID(sourceArchive, pcapMember, fileName any) string {
	return StableID(sourceArchive, pcapMember, fileName)
}

func MakeSplitGroup(sourceArchive, pcapMember, fileName, captureID any) string {
	text := idText(captureID)
	if text != "" {
		return text
	}
	return MakeCaptureID(sourceArchive, pcapMember, fileName)
}

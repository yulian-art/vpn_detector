package labels

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestNonVPNRootStrongAndNoDefaultVPN(t *testing.T) {
	root := t.TempDir()
	nonVPN := filepath.Join(root, "nonvpn")
	if err := os.Mkdir(nonVPN, 0755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(nonVPN, "normal_browse.pcapng")
	if err := os.WriteFile(pcap, []byte("mock"), 0644); err != nil {
		t.Fatal(err)
	}
	samples, err := IterInputSamples([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("samples=%d, want 1", len(samples))
	}
	vote := LFNonVPNRoot(samples[0], nonVPN)
	if vote == nil || vote.Value != 0 || vote.Confidence != "strong" {
		t.Fatalf("vote=%+v, want strong nonvpn vote", vote)
	}
	if vpnVote := LFVPNRoot(samples[0], filepath.Join(root, "vpn")); vpnVote != nil {
		t.Fatalf("unexpected vpn vote: %+v", vpnVote)
	}
}

func TestZipUnderVPNRootInheritsStrongLabel(t *testing.T) {
	root := t.TempDir()
	vpnRoot := filepath.Join(root, "vpn")
	if err := os.Mkdir(vpnRoot, 0755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(vpnRoot, "captures.zip")
	w, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(w)
	f, err := zw.Create("cap/a.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("mock")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	samples, err := IterInputSamples([]string{archive})
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("samples=%d, want 1", len(samples))
	}
	vote := LFVPNRoot(samples[0], vpnRoot)
	if vote == nil || vote.Value != 1 || vote.Confidence != "strong" {
		t.Fatalf("vote=%+v, want strong vpn vote", vote)
	}
}

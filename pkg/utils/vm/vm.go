package vm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "embed"

	"github.com/adrg/xdg"
	"github.com/anatol/vmtest"
	scp "github.com/bramvdbogaerde/go-scp"
	"github.com/kdomanski/iso9660"
	"github.com/klauspost/cpuid/v2"
	"golang.org/x/crypto/ssh"
)

//go:embed cloud-config.yaml
var userData string

//go:embed metadata.yaml
var metaData string

//go:embed network-config.yaml
var networkConfig string

// RunTestInVM runs the test as root inside a linux VM using QEMU.
func RunTestInVM(t *testing.T) bool {
	t.Helper()

	if cpuid.CPU.VM() {
		// We are the child running in the VM, nothing we need to do.
		return true
	}

	// Use an XDG directory for the image
	imageDir, err := xdg.CacheFile("vmtest")
	if err != nil {
		t.Fatalf("failed to get cache directory: %v", err)
		return false
	}
	imagePath := filepath.Join(imageDir, "debian-12-generic.qcow2")

	// Download the image if not already present
	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		imageURL := fmt.Sprintf("https://cdimage.debian.org/images/cloud/bookworm/20250428-2096/debian-12-generic-amd64-20250428-2096.qcow2")

		t.Logf("Downloading image from %s...\n", imageURL)

		if err := os.MkdirAll(filepath.Dir(imagePath), 0o755); err != nil {
			t.Fatalf("failed to create cache directory: %v", err)
			return false
		}

		resp, err := http.Get(imageURL)
		if err != nil {
			t.Fatalf("failed to download image: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status code: %d", resp.StatusCode)
			return false
		}

		out, err := os.Create(imagePath)
		if err != nil {
			t.Fatalf("failed to create image file: %v", err)
			return false
		}
		defer out.Close()

		if _, err := io.Copy(out, resp.Body); err != nil {
			t.Fatalf("failed to save image: %v", err)
			return false
		}
	} else {
		t.Logf("Using existing image at %s\n", imagePath)
	}

	tempDir := t.TempDir()

	cloudInitISOPath := filepath.Join(tempDir, "cloud-init.iso")
	cloudInitISOFile, err := os.Create(cloudInitISOPath)
	if err != nil {
		t.Fatalf("failed to create cloud-init ISO file: %v", err)
		return false
	}

	t.Logf("Creating cloud-init ISO at %s...\n", cloudInitISOPath)

	err = createCloudInitISO(cloudInitISOFile, userData, networkConfig, metaData)
	_ = cloudInitISOFile.Close()
	if err != nil {
		t.Fatalf("failed to create cloud-init ISO: %v", err)
		return false
	}

	qemuParams := []string{
		"-m", "1024M",
		"-netdev", "user,id=net0,hostfwd=tcp::10022-:22",
		"-device", "e1000,netdev=net0,mac=52:54:00:12:34:56",
		"-snapshot",
	}

	if runtime.GOOS == "linux" {
		qemuParams = append(qemuParams, "-cpu", "host")
		qemuParams = append(qemuParams, "-enable-kvm")
	} else if runtime.GOOS == "darwin" {
		qemuParams = append(qemuParams, "-machine", "type=q35,accel=tcg")
	}

	// Launch the QEMU VM using vmtest
	opts := vmtest.QemuOptions{
		Architecture:    vmtest.QEMU_X86_64,
		OperatingSystem: vmtest.OS_LINUX,
		Disks: []vmtest.QemuDisk{
			{Path: imagePath, Format: "qcow2"},
		},
		Params:  qemuParams,
		Timeout: 90 * time.Second,
		Verbose: testing.Verbose(),
		CdRom:   cloudInitISOPath,
	}

	qemu, err := vmtest.NewQemu(&opts)
	if err != nil {
		t.Fatalf("failed to create QEMU instance: %v", err)
	}
	t.Cleanup(qemu.Shutdown)

	_, testSourceFile, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatalf("failed to get test file path")
		return false
	}

	t.Logf("Compiling test binary from %s...\n", testSourceFile)

	// Compile the test binary
	testBinary := filepath.Join(tempDir, "testbin")
	cmd := exec.Command("go", "test", "-c", "-o", testBinary, testSourceFile)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile test binary: %v", err)
		return false
	}
	t.Cleanup(func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	})

	t.Logf("Waiting for VM to boot...\n")

	config := &ssh.ClientConfig{
		User: "apoxy",
		Auth: []ssh.AuthMethod{
			ssh.Password("apoxy"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Wait for SSH to become available
	var conn *ssh.Client
	for i := 0; i < 10; i++ {
		conn, err = ssh.Dial("tcp", "localhost:10022", config)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		t.Fatalf("failed to connect to VM via SSH: %v", err)
		return false
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("failed to close SSH connection: %v", err)
		}
	})

	t.Logf("Copy test binary to VM...\n")

	// Copy the test binary to the VM using SCP
	scpClient, err := scp.NewClientBySSH(conn)
	if err != nil {
		t.Fatalf("failed to create SCP client: %v", err)
		return false
	}
	t.Cleanup(scpClient.Close)

	f, err := os.Open(testBinary)
	if err != nil {
		t.Fatalf("failed to open compiled binary: %v", err)
		return false
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Logf("failed to close compiled binary: %v", err)
		}
	})

	if err := scpClient.CopyFile(t.Context(), f, "testbin", "0755"); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("failed to copy binary to VM: %v", err)
		return false
	}

	// Run the test binary in the VM
	sess, err := conn.NewSession()
	if err != nil {
		t.Fatalf("failed to create SSH session: %v", err)
		return false
	}
	defer sess.Close()

	testCmd := "sudo -E ./testbin"
	if testing.Verbose() {
		testCmd += " -test.v"
	}
	testCmd += " -test.run " + t.Name()

	output, err := sess.CombinedOutput(testCmd)

	t.Log(string(output))

	if err != nil {
		t.Fatalf("failed to run test binary in VM: %v", err)
		return false
	}

	return false
}

func createCloudInitISO(w io.Writer, userData, networkConfig, metaData string) error {
	writer, err := iso9660.NewWriter()
	if err != nil {
		return fmt.Errorf("failed to create iso9660 writer: %w", err)
	}

	if err := writer.AddFile(bytes.NewReader([]byte(userData)), "user-data"); err != nil {
		return fmt.Errorf("failed to add user-data to ISO: %w", err)
	}

	if err := writer.AddFile(bytes.NewReader([]byte(networkConfig)), "network-config"); err != nil {
		return fmt.Errorf("failed to add network-config to ISO: %w", err)
	}

	if err := writer.AddFile(bytes.NewReader([]byte(metaData)), "meta-data"); err != nil {
		return fmt.Errorf("failed to add meta-data to ISO: %w", err)
	}

	if err := writer.WriteTo(w, "cidata"); err != nil {
		return fmt.Errorf("failed to write ISO: %w", err)
	}

	if err := writer.Cleanup(); err != nil {
		return fmt.Errorf("failed to cleanup iso9660 writer: %w", err)
	}

	return nil
}

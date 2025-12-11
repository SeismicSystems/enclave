package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func computeMAC(passphrase string, headerFile string) ([]byte, error) {
	headerData, err := os.ReadFile(headerFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}

	h := hmac.New(sha256.New, []byte(passphrase))
	h.Write(headerData)
	return h.Sum(nil), nil
}

func verifyMAC(passphrase string, headerFile string, expectedMAC []byte) error {
	actualMAC, err := computeMAC(passphrase, headerFile)
	if err != nil {
		return err
	}

	if !hmac.Equal(actualMAC, expectedMAC) {
		return fmt.Errorf("header MAC verification failed")
	}

	return nil
}

func setPassphrase() error {
	// Check if already mounted
	if checkMounted() {
		return fmt.Errorf("encrypted disk already mounted")
	}

	// Check if key exists
	if _, err := os.Stat(keyFile); err != nil {
		return fmt.Errorf("SSH key not set, provide public key via HTTP first")
	}

	fmt.Print("Enter passphrase: ")
	var passphrase string
	fmt.Scanln(&passphrase)

	// Check if LUKS container exists
	cmd := exec.Command("cryptsetup", "isLuks", devicePath)
	isLuks := cmd.Run() == nil

	if isLuks {
		return mountExistingDisk(passphrase)
	}
	// LUKS not found, format new disk

	if err := setupNewDisk(passphrase); err != nil {
		return err
	}
	return setupMountDirs()
}

func setupNewDisk(passphrase string) error {
	// Clean up any existing header file
	os.Remove(headerFile)

	// Format with LUKS2 using detached header
	// Leave 32769 sectors (16MB + 1 sector) free at start for header and MAC
	// This creates a 16MB LUKS2 header file separately from the device
	log.Println("Formatting disk with LUKS2...")
	cmd := exec.Command("cryptsetup", "luksFormat", "--type", "luks2",
		"--header", headerFile, "--align-payload", "32769", "-q", devicePath)
	cmd.Stdin = strings.NewReader(passphrase)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("formatting disk: %v", err)
	}

	// Get the SSH key
	key, err := os.ReadFile(keyFile)
	if err != nil {
		cleanupMount()
		return fmt.Errorf("reading SSH key file: %v", err)
	}

	token := Token{
		Type:     "user",
		Keyslots: []string{},
		UserData: map[string]string{
			"metadata": string(key),
		},
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		cleanupMount()
		return fmt.Errorf("marshaling token JSON: %v", err)
	}

	// Import the token into the LUKS header
	log.Println("Saving searcher SSH key...")
	cmd = exec.Command("cryptsetup", "token", "import", "--token-id", "1", "--header", headerFile, "/dev/null")
	cmd.Stdin = strings.NewReader(string(tokenJSON))
	if err := cmd.Run(); err != nil {
		cleanupMount()
		return fmt.Errorf("importing token to LUKS header: %v", err)
	}

	// Write header to the device
	log.Println("Writing header to disk...")
	cmd = exec.Command("cryptsetup", "luksHeaderRestore", devicePath,
		"--header-backup-file", headerFile)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restoring header to device: %v", err)
	}

	// Compute MAC of the header
	mac, err := computeMAC(passphrase, headerFile)
	if err != nil {
		return fmt.Errorf("computing header MAC: %v", err)
	}

	// Store the MAC in the 32769th sector (after the 16MB header)
	cmd = exec.Command("dd", "of="+devicePath, "bs=512", "seek=32768", "count=1", "conv=notrunc")
	cmd.Stdin = bytes.NewReader(mac)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("writing MAC to device: %v", err)
	}

	// Open the LUKS container using detached header
	cmd = exec.Command("cryptsetup", "open", "--header", headerFile, devicePath, mapperName)
	cmd.Stdin = strings.NewReader(passphrase)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("opening LUKS device: %v", err)
	}

	// Create ext4 filesystem
	log.Println("Creating ext4 filesystem...")
	if err := exec.Command("mkfs.ext4", mapperDevice).Run(); err != nil {
		exec.Command("cryptsetup", "close", mapperName).Run()
		return fmt.Errorf("creating filesystem: %v", err)
	}

	// Mount the filesystem
	os.MkdirAll(mountPoint, 0755)
	if err := exec.Command("mount", mapperDevice, mountPoint).Run(); err != nil {
		exec.Command("cryptsetup", "close", mapperName).Run()
		return fmt.Errorf("mounting filesystem: %v", err)
	}

	os.Remove(headerFile)

	fmt.Println("Encrypted disk initialized and mounted successfully")
	return nil
}

func mountExistingDisk(passphrase string) (err error) {
	// Remove existing header file, if any
	os.Remove(headerFile)

	// Extract the header from the device
	log.Println("Extracting LUKS header...")
	cmd := exec.Command("cryptsetup", "luksHeaderBackup", devicePath,
		"--header-backup-file", headerFile)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("extracting LUKS header: %v", err)
	}

	// Remove header afterwards
	defer os.Remove(headerFile)

	// Read the expected MAC from the 32769th sector
	var macBuf bytes.Buffer
	cmd = exec.Command("dd", "if="+devicePath, "bs=512", "skip=32768", "count=1")
	cmd.Stdout = &macBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reading expected MAC from device: %v", err)
	}
	sector := macBuf.Bytes()
	if len(sector) < 32 {
		return fmt.Errorf("incomplete MAC read from device")
	}
	expectedMAC := sector[:32]

	// Verify the header MAC
	log.Println("Verifying header integrity...")
	if err := verifyMAC(passphrase, headerFile, expectedMAC); err != nil {
		return fmt.Errorf("verifying header MAC: %v", err)
	}

	// Open the LUKS container using the verified detached header
	cmd = exec.Command("cryptsetup", "open", "--header", headerFile, devicePath, mapperName)
	cmd.Stdin = strings.NewReader(passphrase)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("opening LUKS device: %v", err)
	}

	defer func() {
		// err is named return value
		if err != nil {
			exec.Command("cryptsetup", "close", mapperName).Run()
		}
	}()

	log.Println("Resizing disk (if needed)...")

	// Resize the LUKS container to use full device size, if physical disk size was increased
	cmd = exec.Command("cryptsetup", "resize", "--header", headerFile, mapperName)
	cmd.Stdin = strings.NewReader(passphrase)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("resizing LUKS device: %v", err)
	}

	// Run e2fsck to fix any filesystem issues before resizing
	//
	// Note: This takes ~10s on multi-TB disks, not too bad
	// If optimizations will be required, we can skip all resizing steps,
	// if size didn't change
	cmd = exec.Command("e2fsck", "-yf", mapperDevice)
	if out, err := cmd.CombinedOutput(); err != nil {
		var osErr *exec.ExitError
		if errors.As(err, &osErr) && osErr.ExitCode() == 1 {
			// Exit code 1 means filesystem errors were corrected
			// which is acceptable in our case
			log.Println("e2fsck: filesystem errors were corrected")
		} else {
			return fmt.Errorf("running 'e2fsck -yf %v', out: '%s': %v", mapperDevice, string(out), err)
		}
	}

	// Resize ext4 filesystem to fill the cryptdisk
	cmd = exec.Command("resize2fs", mapperDevice)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running 'resize2fs %v': %v", mapperDevice, err)
	}

	log.Println("Mounting disk...")
	os.MkdirAll(mountPoint, 0755)
	if err := exec.Command("mount", mapperDevice, mountPoint).Run(); err != nil {
		return fmt.Errorf("mounting filesystem: %v", err)
	}

	log.Println("Encrypted disk mounted successfully!")
	return nil
}

func setupMountDirs() error {
	dirs := []string{"searcher", "delayed_logs", "searcher_logs"}
	for _, dir := range dirs {
		path := fmt.Sprintf("%s/%s", mountPoint, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %v", path, err)
		}
	}

	if err := os.Chown(fmt.Sprintf("%s/searcher", mountPoint), 1000, 1000); err != nil {
		return fmt.Errorf("setting ownership for searcher: %v", err)
	}
	if err := os.Chown(fmt.Sprintf("%s/searcher_logs", mountPoint), 1000, 1000); err != nil {
		return fmt.Errorf("setting ownership for searcher_logs: %v", err)
	}
	if err := os.Chmod(fmt.Sprintf("%s/searcher_logs", mountPoint), 0755); err != nil {
		return fmt.Errorf("setting permissions for searcher_logs: %v", err)
	}

	return nil
}

func checkMounted() bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), " "+mountPoint+" ")
}

func cleanupMount() {
	exec.Command("umount", mountPoint).Run()
	exec.Command("cryptsetup", "close", mapperName).Run()
	os.Remove(headerFile)
}

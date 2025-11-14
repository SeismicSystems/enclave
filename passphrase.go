package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func generateRandomPassphrase() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random passphrase: %v", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

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

func setPassphrase() {
	fmt.Print("Enter passphrase: ")
	var passphrase string
	fmt.Scanln(&passphrase)

	initializeWithPassphrase(passphrase)
}

func initializeRandom() {
	passphrase, err := generateRandomPassphrase()
	if err != nil {
		log.Fatalf("Error generating passphrase: %v", err)
	}

	log.Println("Automatically initializing disk with random passphrase...")
	initializeWithPassphrase(passphrase)
}

func initializeWithPassphrase(passphrase string) {
	// Check if already mounted
	if checkMounted() {
		log.Fatalln("Error: Encrypted disk already setup")
	}

	// Check if key exists
	if _, err := os.Stat(keyFile); err != nil {
		log.Fatalln("Error: SSH key not set. Provide public key via HTTP first.")
	}

	// Check if config exists
	if _, err := os.Stat(tempConfigFile); err != nil {
		log.Fatalln("Error: Config not found. Provide configuration via HTTP first.")
	}

	// Check if LUKS container exists
	cmd := exec.Command("cryptsetup", "isLuks", devicePath)
	isNewSetup := cmd.Run() != nil

	if isNewSetup {
		setupNewDisk(passphrase)
		setupMountDirs()
	} else {
		mountExistingDisk(passphrase)
	}
}

func setupNewDisk(passphrase string) {
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
		log.Fatalf("Error formatting disk: %v\n", err)
	}

	// Get the SSH key
	key, err := os.ReadFile(keyFile)
	if err != nil {
		cleanupMount()
		log.Fatalf("Error reading SSH key file: %v", err)
	}

	userData := map[string]string{
		"ssh_key":  string(key),
		"metadata": string(key), // Keep for backwards compatibility
	}

	// Read and include the full config if it exists
	if configData, err := os.ReadFile(tempConfigFile); err == nil {
		userData["config"] = string(configData)
		log.Println("Including configuration data in LUKS header")
	}

	token := Token{
		Type:     "user",
		Keyslots: []string{},
		UserData: userData,
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		cleanupMount()
		log.Fatalf("Error marshaling token JSON: %v", err)
	}

	// Import the token into the LUKS header
	log.Println("Saving searcher SSH key...")
	cmd = exec.Command("cryptsetup", "token", "import", "--token-id", "1", "--header", headerFile, "/dev/null")
	cmd.Stdin = strings.NewReader(string(tokenJSON))
	if err := cmd.Run(); err != nil {
		cleanupMount()
		log.Fatalf("Error importing token to LUKS header: %v\n", err)
	}

	// Write header to the device
	log.Println("Writing header to disk...")
	cmd = exec.Command("cryptsetup", "luksHeaderRestore", devicePath,
		"--header-backup-file", headerFile)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error restoring header to device: %v\n", err)
	}

	// Compute MAC of the header
	mac, err := computeMAC(passphrase, headerFile)
	if err != nil {
		log.Fatalf("Error computing header MAC: %v\n", err)
	}

	// Store the MAC in the 32769th sector (after the 16MB header)
	cmd = exec.Command("dd", "of="+devicePath, "bs=512", "seek=32768", "count=1", "conv=notrunc")
	cmd.Stdin = bytes.NewReader(mac)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error writing MAC to device: %v\n", err)
	}

	// Open the LUKS container using detached header
	cmd = exec.Command("cryptsetup", "open", "--header", headerFile, devicePath, mapperName)
	cmd.Stdin = strings.NewReader(passphrase)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error opening LUKS device: %v\n", err)
	}

	// Create ext4 filesystem
	log.Println("Creating ext4 filesystem...")
	if err := exec.Command("mkfs.ext4", mapperDevice).Run(); err != nil {
		exec.Command("cryptsetup", "close", mapperName).Run()
		log.Fatalf("Error creating filesystem: %v\n", err)
	}

	// Mount the filesystem
	os.MkdirAll(mountPoint, 0755)
	if err := exec.Command("mount", mapperDevice, mountPoint).Run(); err != nil {
		exec.Command("cryptsetup", "close", mapperName).Run()
		log.Fatalf("Error mounting filesystem: %v\n", err)
	}

	os.Remove(headerFile)

	fmt.Println("Encrypted disk initialized and mounted successfully")
}

func mountExistingDisk(passphrase string) {
	// Clean up any existing header file
	os.Remove(headerFile)

	// Extract the header from the device
	log.Println("Extracting LUKS header...")
	cmd := exec.Command("cryptsetup", "luksHeaderBackup", devicePath,
		"--header-backup-file", headerFile)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error extracting LUKS header: %v\n", err)
	}

	// Read the expected MAC from the 32769th sector
	var macBuf bytes.Buffer
	cmd = exec.Command("dd", "if="+devicePath, "bs=512", "skip=32768", "count=1")
	cmd.Stdout = &macBuf
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error reading expected MAC from device: %v\n", err)
	}
	sector := macBuf.Bytes()
	if len(sector) < 32 {
		log.Fatalln("Error: Incomplete MAC read from device")
	}
	expectedMAC := sector[:32]

	// Verify the header MAC
	log.Println("Verifying header integrity...")
	if err := verifyMAC(passphrase, headerFile, expectedMAC); err != nil {
		os.Remove(headerFile)
		log.Fatalf("Error verifying header MAC: %v\n", err)
	}

	// Open the LUKS container using the verified detached header
	cmd = exec.Command("cryptsetup", "open", "--header", headerFile, devicePath, mapperName)
	cmd.Stdin = strings.NewReader(passphrase)
	if err := cmd.Run(); err != nil {
		os.Remove(headerFile)
		log.Fatalf("Error opening LUKS device: %v\n", err)
	}

	// Clean up header file
	os.Remove(headerFile)

	// Mount the filesystem
	os.MkdirAll(mountPoint, 0755)
	if err := exec.Command("mount", mapperDevice, mountPoint).Run(); err != nil {
		exec.Command("cryptsetup", "close", mapperName).Run()
		log.Fatalf("Error mounting filesystem: %v\n", err)
	}

	// Copy config to persistent storage if it doesn't exist there yet
	copyConfigToPersistent()

	fmt.Println("Encrypted disk mounted successfully")
}

func copyConfigToPersistent() {
	// Copy config from temp location to persistent location
	if configData, err := os.ReadFile(tempConfigFile); err == nil {
		if err := os.MkdirAll(filepath.Dir(persistentConfigFile), 0755); err != nil {
			log.Printf("Warning: Could not create persistent config directory: %v", err)
			return
		}
		if err := os.WriteFile(persistentConfigFile, configData, 0644); err != nil {
			log.Printf("Warning: Could not copy config to persistent storage: %v", err)
			return
		}
		// Ensure file is readable by all users
		if err := os.Chmod(persistentConfigFile, 0644); err != nil {
			log.Printf("Warning: Could not set permissions on config file: %v", err)
		}
		log.Printf("Config copied to %s", persistentConfigFile)
	}
}

func setupMountDirs() {
	dirs := []string{"searcher", "delayed_logs", "searcher_logs", "conf"}
	for _, dir := range dirs {
		path := fmt.Sprintf("%s/%s", mountPoint, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			log.Fatalf("Error creating directory %s: %v\n", path, err)
		}
	}

	if err := os.Chown(fmt.Sprintf("%s/searcher", mountPoint), 1000, 1000); err != nil {
		log.Fatalf("Error setting ownership for searcher: %v\n", err)
	}
	if err := os.Chown(fmt.Sprintf("%s/searcher_logs", mountPoint), 1000, 1000); err != nil {
		log.Fatalf("Error setting ownership for searcher_logs: %v\n", err)
	}
	if err := os.Chmod(fmt.Sprintf("%s/searcher_logs", mountPoint), 0755); err != nil {
		log.Fatalf("Error setting permissions for searcher_logs: %v\n", err)
	}

	// Copy config to persistent storage
	copyConfigToPersistent()
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

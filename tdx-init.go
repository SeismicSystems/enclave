package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	keyFile      = "/etc/searcher_key"
	sshDir       = "/home/searcher/.ssh"
	mountPoint   = "/persistent"
	mapperName   = "cryptdisk"
	mapperDevice = "/dev/mapper/" + mapperName
	httpPort     = "8080"
	headerFile   = "/tmp/luksheader.img"
)

var devicePath string

type Token struct {
	Type     string            `json:"type"`
	Keyslots []string          `json:"keyslots"`
	UserData map[string]string `json:"user_data"`
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("Usage: tdx-init [wait-for-key|set-passphrase]")
	}

	os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin")

	for {
		if d := lookupPersistentDisk(); d != "" {
			devicePath = d
			break
		}

		fmt.Println("Waiting for persistent disk device to appear...")
		time.Sleep(2 * time.Second)
	}

	switch os.Args[1] {
	case "wait-for-key":
		waitForKey()
	case "set-passphrase":
		if err := setPassphrase(); err != nil {
			log.Fatalf("Error: %v\n", err)
		}
	default:
		log.Fatalf("Unknown command: %s\n", os.Args[1])
	}
}

// lookupPersistentDisk tries to find the persistent disk device
// by checking a set of glob patterns. Returns the first matching device path,
// or empty string if none found.
// It reads glob patterns from /etc/tdx-init/disk-glob if the file exists,
// otherwise uses a default pattern for Azure persistent disks.
func lookupPersistentDisk() string {
	// Default glob is Azure persistent disk path
	var globs = []string{"/dev/disk/by-path/*10"}

	// As we call tdx-init from searchersh without any arguments,
	// it's easier to read path from a file instead of flag/env.
	if data, err := os.ReadFile("/etc/tdx-init/disk-glob"); err == nil {
		if s := strings.TrimSpace(string(data)); s != "" {
			globs = strings.Split(s, "\n")
		}
	}

	for _, g := range globs {
		devices, err := filepath.Glob(g)
		if err == nil && len(devices) > 0 {
			if len(devices) > 1 {
				fmt.Printf("Warning: multiple devices found by glob '%v': %v\n", g, devices)
			}
			fmt.Printf("Using persistent disk device: %s\n", devices[0])
			return devices[0]
		}
	}
	return ""
}

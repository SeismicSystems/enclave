package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// InitConfig is the JSON structure expected from the POST request
type InitConfig struct {
	SSHKeys []string     `json:"ssh_keys"`
	Domain  DomainConfig `json:"domain"`
	Args    ArgsConfig   `json:"args"`
}

type DomainConfig struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type ArgsConfig struct {
	Enclave string `json:"enclave"`
	Reth    string `json:"reth"`
	Summit  string `json:"summit"`
}

const configFile = "/etc/tdx-init/config.json"

func waitForKey() {
	// Check if LUKS container exists
	cmd := exec.Command("cryptsetup", "isLuks", devicePath)
	if cmd.Run() == nil {
		// LUKS exists, extract config from header
		log.Println("Found existing LUKS container, extracting config...")
		cmd := exec.Command("cryptsetup", "token", "export", "--token-id", "1", devicePath)
		output, err := cmd.Output()
		if err != nil {
			log.Fatalf("Error exporting LUKS token: %v", err)
		}

		var token Token
		if err := json.Unmarshal(output, &token); err != nil {
			log.Fatalf("Error parsing token JSON: %v", err)
		}

		// Extract config from token
		configData, ok := token.UserData["config"]
		if !ok {
			// Fallback to old format for backwards compatibility
			keyData, ok := token.UserData["metadata"]
			if !ok {
				log.Fatalln("Error: No SSH key found in token")
			}
			// Old format - single key
			writeKeys([]string{string(keyData)})
			log.Printf("Key extracted from LUKS header (legacy format)")
			return
		}

		// New format - parse full config
		var config InitConfig
		if err := json.Unmarshal([]byte(configData), &config); err != nil {
			log.Fatalf("Error parsing config from LUKS header: %v", err)
		}

		// Write SSH keys
		if len(config.SSHKeys) == 0 {
			log.Fatalln("Error: No SSH keys found in config")
		}
		writeKeys(config.SSHKeys)

		// Write full config to disk
		if err := os.MkdirAll(filepath.Dir(configFile), 0755); err != nil {
			log.Printf("Warning: Could not create config directory: %v", err)
		}
		if err := os.WriteFile(configFile, []byte(configData), 0600); err != nil {
			log.Printf("Warning: Could not write config file: %v", err)
		} else {
			log.Printf("Config extracted and written to %s", configFile)
		}

		log.Printf("%d SSH key(s) extracted from LUKS header", len(config.SSHKeys))
		return
	}

	// No LUKS container, start HTTP server to wait for key
	log.Printf("No LUKS container found, starting HTTP server on port %s...", httpPort)
	log.Println("Waiting for config to be provided via HTTP...")

	done := make(chan struct{})

	// Handler for SSH keys and domain config
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "Only POST method is allowed")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Error reading request: %v", err)
			return
		}

		// Parse JSON config
		var config InitConfig
		if err := json.Unmarshal(body, &config); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Invalid JSON: %v", err)
			return
		}

		// Validate SSH keys
		if len(config.SSHKeys) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "ssh_keys array cannot be empty")
			return
		}
		for i, key := range config.SSHKeys {
			matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]{68}$`, key)
			if !matched {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "Invalid ssh_keys[%d] format, expected base64-encoded OpenSSH ed25519 public key", i)
				return
			}
		}

		// Write SSH keys
		writeKeys(config.SSHKeys)

		// Re-marshal with nice indentation
		formattedJSON, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			log.Printf("Warning: Could not format JSON: %v", err)
			formattedJSON = body // Fallback to raw body
		}

		// Save formatted JSON to disk
		if err := os.MkdirAll(filepath.Dir(configFile), 0755); err != nil {
			log.Printf("Warning: Could not create config directory: %v", err)
		}
		if err := os.WriteFile(configFile, formattedJSON, 0600); err != nil {
			log.Printf("Warning: Could not write config file: %v", err)
		} else {
			log.Printf("Config written to %s", configFile)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Configuration received and stored successfully")

		close(done)
	})

	srv := &http.Server{Addr: ":" + httpPort}
	go srv.ListenAndServe()

	<-done

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)

	log.Printf("Configuration received via HTTP and written to disk!")
}

var keyMu sync.Mutex

func writeKeys(keys []string) {
	keyMu.Lock()
	defer keyMu.Unlock()

	os.MkdirAll(sshDir, 0700)

	// Set ownership of .ssh directory
	if err := os.Chown(sshDir, 1000, 1000); err != nil {
		log.Printf("Warning: Could not set ownership on .ssh dir: %v", err)
	}

	// Write authorized_keys with correct permissions
	authKeysFile := filepath.Join(sshDir, "authorized_keys")
	f, err := os.OpenFile(authKeysFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Error opening authorized_keys: %v", err)
	}
	defer f.Close()

	// Write all keys to authorized_keys
	for _, key := range keys {
		if _, err := f.WriteString("no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 " + key + "\n"); err != nil {
			log.Fatalf("Error writing to authorized_keys: %v", err)
		}
	}

	// Set ownership of authorized_keys file
	if err := os.Chown(authKeysFile, 1000, 1000); err != nil {
		log.Printf("Warning: Could not set ownership on authorized_keys: %v", err)
	}

	// Write first key to separate key file (still needed for the container)
	if err := os.WriteFile(keyFile, []byte(keys[0]), 0600); err != nil {
		log.Fatalf("Error writing key file: %v", err)
	}

	log.Printf("Wrote %d SSH key(s) to authorized_keys", len(keys))
}

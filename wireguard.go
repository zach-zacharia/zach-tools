package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/go-routeros/routeros"
)

func generateKeys() (string, string, error) {
	// Generate private key
	privateKeyCmd := exec.Command("wg", "genkey")
	privateKeyOut, err := privateKeyCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}
	privateKey := strings.TrimSpace(string(privateKeyOut))

	// Generate public key from private key
	publicKeyCmd := exec.Command("sh", "-c", fmt.Sprintf("echo %s | wg pubkey", privateKey))
	publicKeyOut, err := publicKeyCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate public key: %v", err)
	}
	publicKey := strings.TrimSpace(string(publicKeyOut))

	return privateKey, publicKey, nil
}

func createClientConfig(privateKey, publicKey, endpoint, allowedIPs, clientIP string) string {
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, privateKey, clientIP, publicKey, endpoint, allowedIPs)

	return config
}

func saveConfigToFile(config, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(config)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}

func main() {
	// Generate WireGuard keys
	privateKey, publicKey, err := generateKeys()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Print generated keys (for debugging purposes)
	fmt.Println("Private Key:", privateKey)
	fmt.Println("Public Key:", publicKey)

	// MikroTik connection details
	host := "172.16.12.1:8728" // Ganti dengan alamat IP dan port MikroTik Anda
	user := "titikkoma"
	pass := "titikkoma"

	// WireGuard client details
	serverPublicKey := "WJFWXjyXTzH6irpUBPR4xQ6hOJxmy/ZIF2YgHk09f0w=" // Ganti dengan kunci publik server WireGuard Anda
	endpointAddress := "172.16.12.1:13231"                            // Ganti dengan alamat IP atau nama domain server WireGuard Anda
	allowedIPs := "0.0.0.0/0"

	// Connect to MikroTik
	client, err := routeros.Dial(host, user, pass)
	if err != nil {
		fmt.Println("Failed to connect to MikroTik:", err)
		return
	}
	defer client.Close()

	// Prompt user for client IP address
	fmt.Print("Enter client IP address (e.g., 10.0.99.2/32): ")
	reader := bufio.NewReader(os.Stdin)
	clientIP, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Failed to read client IP address:", err)
		return
	}
	clientIP = strings.TrimSpace(clientIP)

	// Add WireGuard client
	cmd := []string{
		"/interface/wireguard/peers/add",
		"=interface=wg0",
		fmt.Sprintf("=public-key=%s", publicKey),
		fmt.Sprintf("=endpoint-address=%s", strings.Split(endpointAddress, ":")[0]),
		fmt.Sprintf("=endpoint-port=%s", strings.Split(endpointAddress, ":")[1]),
		fmt.Sprintf("=allowed-address=%s", allowedIPs),
	}

	_, err = client.RunArgs(cmd)
	if err != nil {
		fmt.Println("Failed to add WireGuard peer:", err)
		return
	}

	// Create client config
	clientConfig := createClientConfig(privateKey, serverPublicKey, endpointAddress, allowedIPs, clientIP)

	// Save client config to file
	filePath := "/etc/wireguard/wg0.conf" // Ganti dengan path yang diinginkan
	err = saveConfigToFile(clientConfig, filePath)
	if err != nil {
		fmt.Println("Failed to save config to file:", err)
		return
	}
	fmt.Println("WireGuard client configuration saved to", filePath)

	// Now bring up the WireGuard interface using wg-quick
	wgQuickCmd := exec.Command("wg-quick", "up", "wg0")
	output, err := wgQuickCmd.CombinedOutput()
	if err != nil {
		fmt.Println("Failed to bring up WireGuard interface:", err)
		fmt.Println("Output:", string(output))
		return
	}

	fmt.Println("Menyala Abangku.")
}

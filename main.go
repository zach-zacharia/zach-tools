package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-routeros/routeros"
)

func main() {
	server := gin.Default()

	server.Static("/css", "./css")
	server.Static("/img", "./img")
	server.Static("/js", "./js")
	server.Static("/lib", "./lib")
	server.Static("/scss", "./scss")
	server.LoadHTMLGlob("static/*.html")

	server.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	server.GET("/wireguard", func(c *gin.Context) {
		c.HTML(http.StatusOK, "wireguard.html", nil)
	})

	server.GET("/portscanner", func(c *gin.Context) {
		c.HTML(http.StatusOK, "portscan.html", nil)
	})

	server.GET("/subnetscanner", func(c *gin.Context) {
		c.HTML(http.StatusOK, "subnetscan.html", nil)
	})

	server.GET("/webshell", func(c *gin.Context) {
		c.HTML(http.StatusOK, "webshell.html", nil)
	})

	server.GET("/alpha", func(c *gin.Context) {
		c.HTML(http.StatusOK, "test.html", nil)
	})

	server.GET("/beta", func(c *gin.Context) {
		c.HTML(http.StatusOK, "tester.html", nil)
	})

	server.POST("/scanport", func(c *gin.Context) {
		// var target string
		target := c.PostForm("portscanip")

		fmt.Printf("Scanning ports for target %s\n", target)

		var wg sync.WaitGroup
		var mutex sync.Mutex

		startPort := 1
		endPort := 65535
		timeout := time.Millisecond * 1000 // Time to scan has a 1000ms limit

		openPorts := make([]int, 0)
		closedPorts := make([]int, 0)

		wg.Add(endPort - startPort + 1)
		for port := startPort; port <= endPort; port++ {
			go func(p int) {
				defer wg.Done()

				address := fmt.Sprintf("%s:%d", target, p)
				conn, err := net.DialTimeout("tcp", address, timeout)
				if err == nil {
					conn.Close()
					mutex.Lock()
					openPorts = append(openPorts, p)
					mutex.Unlock()
				} else {
					mutex.Lock()
					closedPorts = append(closedPorts, p)
					mutex.Unlock()
				}
			}(port)
		}

		// Wait for all goroutines to finish
		wg.Wait()

		// Prepare scan results
		var results string
		results += fmt.Sprint("\nSummary:\n")
		results += fmt.Sprintf("Total Ports: %d\n", endPort-startPort+1)
		results += fmt.Sprintf("Open Ports: %d\n", len(openPorts))
		results += fmt.Sprintf("Closed Ports: %d\n", len(closedPorts))

		// Send results as JSON including download URL
		c.JSON(http.StatusOK, gin.H{
			"ip":      target,
			"results": results,
		})
	})

	server.POST("/scansubnet", func(c *gin.Context) {
		ip := c.PostForm("subnetscanip")
		subnetMask := c.PostForm("subnetscansubnet")

		if ip == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"Error": "IP address is required",
			})
			return
		}

		if subnetMask == "" {
			subnetMask = "/24"
		} else {
			_, _, err := net.ParseCIDR(ip + subnetMask)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"Error": "Invalid subnet mask format: " + err.Error(),
				})
				return
			}
		}

		// Assume a default subnet mask (e.g., /24)

		_, subnet, err := net.ParseCIDR(ip + subnetMask)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"Error": "Invalid IP address or subnet mask: " + err.Error(),
			})
			return
		}

		network := subnet.IP
		broadcast := CalculateBroadcastAddress(network, subnet.Mask)
		firstIP, lastIP := CalculateFirstLastIP(network, broadcast)

		// Prepare JSON response
		response := gin.H{
			"IP":               ip,
			"SubnetMask":       subnetMask,
			"NetworkAddress":   network.String(),
			"BroadcastAddress": broadcast.String(),
			"FirstValidIP":     firstIP.String(),
			"LastValidIP":      lastIP.String(),
		}

		c.JSON(http.StatusOK, response)
	})

	server.POST("/mikrologin", func(c *gin.Context) {
		routerIP := c.PostForm("ip")
		username := c.PostForm("user")
		password := c.PostForm("pass")

		err := mikrotikLogin(routerIP, username, password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		response := gin.H{
			"message": "Successfully logged in",
		}

		c.JSON(http.StatusOK, response)
	})

	server.POST("/mikroadduser", func(c *gin.Context) {
		routerIP := "192.168.56.2"
		username := "admin"
		password := ""
		client, err := routeros.Dial(fmt.Sprintf("%s:8728", routerIP), username, password)
		if err != nil {
			fmt.Errorf("Failed to connect to router: %v", err)
		}
		defer client.Close()
		user := c.PostForm("user")
		group := c.PostForm("group")
		user_password := c.PostForm("pass")

		command := fmt.Sprintf("/user/add =name=%s =group=%s =password=%s", user, group, user_password)
		_, err = client.RunArgs(strings.Split(command, " "))
		if err != nil {
			fmt.Errorf("Failed to add user: %v", err)
		}
		response := gin.H{
			"message": "Successfully added the user",
		}

		c.JSON(http.StatusOK, response)
	})

	server.POST("/mikrowire", func(c *gin.Context) {
		privateKey, publicKey, err := generateKeys()
		if err != nil {
			fmt.Println(err)
			return
		}

		mikrotikIP := c.PostForm("ip")
		mikrotikUser := c.PostForm("user")
		mikrotikPass := c.PostForm("pass")
		mikrotikClientIP := c.PostForm("clientip")

		// serverPublicKey := "WJFWXjyXTzH6irpUBPR4xQ6hOJxmy/ZIF2YgHk09f0w="
		serverPublicKey := "K/S26Ub03rQ/JOeytxlTkO+VqPIw9A2yYEgFsREgBD8="
		endpointAddress := "192.168.56.2:13231"
		allowedIPs := "0.0.0.0/0"

		client, err := routeros.Dial(mikrotikIP, mikrotikUser, mikrotikPass)
		if err != nil {
			fmt.Println("Failed to connect to MikroTik:", err)
			return
		}
		defer client.Close()

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

		clientConfig := createClientConfig(privateKey, serverPublicKey, endpointAddress, allowedIPs, mikrotikClientIP)
		filePath := "./wireconf/wg0.conf" // Ganti dengan path yang diinginkan
		err = saveConfigToFile(clientConfig, filePath)
		if err != nil {
			fmt.Println("Failed to save config to file:", err)
			return
		}
		fmt.Println("WireGuard client configuration saved to", filePath)

		// wgQuickCmd := exec.Command("wg-quick", "up", "wg0")
		// output, err := wgQuickCmd.CombinedOutput()
		// if err != nil {
		// 	fmt.Errorf("Failed to bring up WireGuard interface:", err)
		// 	fmt.Println("Output:", string(output))
		// 	return
		// }

		response := gin.H{
			"message": "Successfully added the peer to the WireGuard interface",
		}

		c.JSON(http.StatusOK, response)
	})

	server.GET("/downloadconf", func(c *gin.Context) {
		filename := "./wireconf/wg0.conf"

		_, err := os.Stat(filename)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "File not found",
			})
			return
		}
		c.Header("Content-Description", "File Transfer")
		c.Header("Content-Transfer-Encoding", "binary")
		c.Header("Content-Disposition", "attachment; filename="+filename)

		c.File(filename)
	})

	server.Run(":4000")
}

func mikrotikLogin(routerIP, username string, password string) error {
	// Connect to the router
	client, err := routeros.Dial(routerIP, username, password)
	if err != nil {
		return fmt.Errorf("Failed to connect to router: %v", err)
	}
	defer client.Close()

	return nil
	// Successfully logged in
}

func CalculateBroadcastAddress(network net.IP, subnetMask net.IPMask) net.IP {
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | ^subnetMask[i]
	}
	return broadcast
}

func CalculateFirstLastIP(network, broadcast net.IP) (firstIP, lastIP net.IP) {
	firstIP = make(net.IP, len(network))
	lastIP = make(net.IP, len(network))

	copy(firstIP, network)
	copy(lastIP, broadcast)

	// Increment the last octet of firstIP for the first valid host
	firstIP[3]++

	// Decrement the last octet of lastIP for the last valid host
	lastIP[3]--

	return firstIP, lastIP
}

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
	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25", privateKey, clientIP, publicKey, endpoint, allowedIPs)
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

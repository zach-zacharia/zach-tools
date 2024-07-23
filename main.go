package main

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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

	server.GET("/ambatukam", func(c *gin.Context) {
		c.HTML(http.StatusOK, "test.html", nil)
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

	server.POST("/wireconf", func(c *gin.Context) {
		privateKey, publicKey, err := generateKeys()
		if err != nil {
			c.JSON(500, gin.H{"error": fmt.Sprintf("Failed to generate keys: %v", err)})
		}

		// Prepare JSON response
		response := gin.H{
			"pubkey":  publicKey,
			"privkey": privateKey,
		}

		c.JSON(http.StatusOK, response)
	})

	server.Run(":4000")
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

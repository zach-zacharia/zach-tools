package main

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
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
		user := fmt.Sprintf("=name=%s", c.PostForm("user"))
		group := fmt.Sprintf("=group=%s", c.PostForm("group"))
		user_password := fmt.Sprintf("=password=%s", c.PostForm("pass"))

		err = runCommand(client, "/user/add", user, group, user_password)
		if err != nil {
			fmt.Errorf("Failed to add user: %v", err)
		}
		response := gin.H{
			"message": "Successfully added the user",
		}

		c.JSON(http.StatusOK, response)
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

// func formatCommand(command string, args ...interface{}) string {
// 	return fmt.Sprintf(command, args...)
// }

func runCommand(client *routeros.Client, command string, args ...string) error {
	// Construct the command and arguments
	cmd := []string{command}
	cmd = append(cmd, args...)

	// Send the command
	reply, err := client.Run(cmd...)
	if err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	// Print the response
	if len(reply.Re) > 0 {
		fmt.Println("Response from router:")
		for _, re := range reply.Re {
			for k, v := range re.Map {
				fmt.Printf("%s: %s\n", k, v)
			}
		}
	} else {
		fmt.Println("No response from router")
	}

	return nil
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

func validateHost(host string) error {
	// Split host into IP and port
	parts := strings.Split(host, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid host format: should be 'IP:port'")
	}

	// Validate IP address
	ip := parts[0]
	if ip == "" {
		return fmt.Errorf("invalid IP address")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format")
	}

	// Validate port number
	portStr := parts[1]
	if portStr == "" {
		return fmt.Errorf("invalid port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port format")
	}
	if port < 0 || port > 65535 {
		return fmt.Errorf("port number out of range (0-65535)")
	}

	return nil
}

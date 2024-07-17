package tools

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func Portscan() {
	r := gin.Default()

	// Serve static files from the root directory
	r.GET("/", func(c *gin.Context) {
		http.FileServer(http.Dir(".")).ServeHTTP(c.Writer, c.Request)
	})
	// Load HTML templates from the templates directory
	r.LoadHTMLGlob("*.html")

	// Route to serve the main HTML template
	r.GET("/portscan", func(c *gin.Context) {
		c.HTML(http.StatusOK, "portscan.html", nil)
	})

	// POST endpoint for handling the scan request
	r.POST("/scan", func(c *gin.Context) {
		var target string
		target = c.PostForm("ip")

		fmt.Printf("Scanning ports for target: %s\n", target)

		var wg sync.WaitGroup
		var mutex sync.Mutex

		startPort := 1
		endPort := 65535
		timeout := time.Millisecond * 1000 // Limit scan time to 1000ms (1 second)

		openPorts := make([]int, 0)
		closedPorts := make([]int, 0)

		// Perform port scanning
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
		results += fmt.Sprintf("\nSummary:\n")
		results += fmt.Sprintf("Total Ports: %d\n", endPort-startPort+1)
		results += fmt.Sprintf("Open Ports: %d\n", len(openPorts))
		results += fmt.Sprintf("Closed Ports: %d\n", len(closedPorts))

		// Generate a unique filename for the text file
		fileName := fmt.Sprintf("scan_results_%s.txt", target)

		// Write scan results to a text file
		err := WriteToFile(fileName, results)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write file"})
			return
		}

		// Send results as JSON including download URL
		c.JSON(http.StatusOK, gin.H{
			"ip":       target,
			"results":  results,
			"download": fmt.Sprintf("/download/%s", fileName), // Provide download URL
		})
	})

	// Endpoint for downloading scan results
	r.GET("/download/:filename", func(c *gin.Context) {
		fileName := c.Param("filename")

		// Set headers for file download
		c.Header("Content-Description", "File Transfer")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
		c.Header("Content-Type", "application/octet-stream")
		c.File(fileName)
	})

	// Run the server
	r.Run(":8080")
}

func Subnetscan() {
	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		http.FileServer(http.Dir(".")).ServeHTTP(c.Writer, c.Request)
	})
	// Load HTML templates from the templates directory
	router.LoadHTMLGlob("*.html")

	// Route to serve the main HTML template
	router.GET("/subnet", func(c *gin.Context) {
		c.HTML(http.StatusOK, "subnetscan.html", nil)
	})

	// Handle subnet calculation
	router.POST("/subnet", func(c *gin.Context) {
		ip := c.PostForm("ip")

		if ip == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"Error": "IP address is required",
			})
			return
		}

		// Assume a default subnet mask (e.g., /24)
		subnetMask := "24"

		_, subnet, err := net.ParseCIDR(ip + "/" + subnetMask)
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

	// Run the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default to port 8090 if not specified
	}
	router.Run(":" + port)
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

// Function to write content to a file
func WriteToFile(fileName, content string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}
	return nil
}

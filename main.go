package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Load HTML templates from the templates directory
	r.LoadHTMLGlob("./")

	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "portscan.html", nil)
	})

	r.POST("/scan", func(c *gin.Context) {
		var target string
		target = c.PostForm("ip")

		fmt.Printf("Scanning ports for target: %s\n", target)

		var wg sync.WaitGroup
		var mutex sync.Mutex

		startPort := 1
		endPort := 65535
		timeout := time.Millisecond * 1000 // Limit scan time to 40ms

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

		// Send results as JSON
		c.JSON(200, gin.H{
			"ip":      target,
			"results": results,
		})
	})

	r.Run(":6000")
}

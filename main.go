package main

import (
	"fmt"
	"net"
	"net/http"
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

	server.GET("/portscanner", func(c *gin.Context) {
		c.HTML(http.StatusOK, "portscan.html", nil)
	})

	server.GET("/subnetscanner", func(c *gin.Context) {
		c.HTML(http.StatusOK, "subnetscan.html", nil)
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

	server.Run(":4000")
}

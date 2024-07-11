package main

import (
    "fmt"
    "github.com/gin-gonic/gin"
    "net"
    "net/http"
    "sync"
    "time"
	"os"
)

func main() {
    r := gin.Default()

    // Serve static files (CSS, JS, images, etc.)
    r.Static("/download", "./download*")

    // Load HTML templates from the templates directory
    r.LoadHTMLGlob("*.html")

    // Route to serve the main HTML template
    r.GET("/", func(c *gin.Context) {
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
        err := writeToFile(fileName, results)
        if err != nil {
            fmt.Println("Error writing to file:", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write file"})
            return
        }

        // Send results as JSON including download URL
        c.JSON(http.StatusOK, gin.H{
            "ip":         target,
            "results":    results,
            "download":   fmt.Sprintf("/download/%s", fileName), // Provide download URL
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

// Function to write content to a file
func writeToFile(fileName, content string) error {
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

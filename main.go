package main

import (
	// "fmt"
	// "net/http"

	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	server := gin.Default()

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

	server.Run(":4000")
}

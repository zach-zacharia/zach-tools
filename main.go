package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
	"github.com/git-gonic/gin"
)

func main() {

}

func PortScan() {
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")
}

func SubnetScan() {

}
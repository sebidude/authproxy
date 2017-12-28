package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

type Logger struct {
}

func (writer Logger) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().Local().Format("2006-01-02 15:04:05.999") + " " + string(bytes))
}

func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		c.Next()

		// after request
		latency := time.Since(t)

		// access the status we are sending
		status := c.Writer.Status()
		logstring := fmt.Sprintf("[ GIN ] %s - %d - %s (%s)",
			c.Request.RemoteAddr,
			status,
			c.Request.RequestURI,
			latency)

		log.Println(logstring)

	}
}

// Copyright 2017 Sebastian Stauch.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

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
	return fmt.Printf("%21s %s",
		time.Now().Local().Format("2006-01-02 15:04:05.999"),
		string(bytes))
}

func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		c.Next()

		// after request
		latency := time.Since(t)

		// access the status we are sending
		status := c.Writer.Status()
		logstring := fmt.Sprintf("[ %s ] %s - %d - %s (%s)",
			c.Request.Host,
			c.Request.RemoteAddr,
			status,
			c.Request.RequestURI,
			latency)

		log.Println(logstring)

	}
}

package main

import (
	"os"

	// "encoding/json"

	"battery-crud-backend/handler"
)

var (
	// router      *gin.Engine
	// once        sync.Once
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	handler.CreateRouter().Run(":" + port)
}


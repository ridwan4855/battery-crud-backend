#!/bin/bash
echo "Building Go binary..."
GOOS=linux GOARCH=amd64 go build -o go-api ./go/main.go

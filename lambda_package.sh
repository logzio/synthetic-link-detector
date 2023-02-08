#!/bin/bash
GOOS=linux GOARCH=amd64 go build -o bootstrap main && chmod 644 $(find . -type f) && chmod 755 $(find . -type d) && zip function.zip bootstrap
rm bootstrap
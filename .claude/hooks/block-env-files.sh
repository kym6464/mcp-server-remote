#!/usr/bin/env bash

input=$(cat)

tool_name=$(echo "$input" | jq -r '.tool_name // empty')
file_path=$(echo "$input" | jq -r '.tool_input.file_path // empty')

if [ "$tool_name" != "Read" ]; then
    exit 0
fi

if [ -z "$file_path" ]; then
    exit 0
fi

filename=$(basename "$file_path")
filename_lower=$(echo "$filename" | tr '[:upper:]' '[:lower:]')

if [ "$filename" = ".env.example" ] || [ "$filename_lower" = ".env.example" ]; then
    exit 0
fi

if [[ "$filename_lower" == .env* ]]; then
    echo "Error: Reading .env files is blocked for security reasons." >&2
    echo "File: $file_path" >&2
    echo "" >&2
    echo "If you need to read environment configuration, please use .env.example instead." >&2
    exit 2
fi

exit 0

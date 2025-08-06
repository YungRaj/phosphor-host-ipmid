#!/bin/bash

INPUT_DIR="securebuffer_raw"
OUTPUT_DIR="securebuffer_with_header"

mkdir -p "$OUTPUT_DIR"

for file in "$INPUT_DIR"/*; do
  filename=$(basename "$file")
  {
    # Write 24 null bytes as the header
    head -c 24 < /dev/zero
    # Append original file content
    cat "$file"
  } > "$OUTPUT_DIR/$filename"
done

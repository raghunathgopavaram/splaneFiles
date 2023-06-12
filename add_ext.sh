#!/bin/bash
branch_name=$(git symbolic-ref --short HEAD)
for file in *; do
  mv "$file" "${file}_$branch_name"
done

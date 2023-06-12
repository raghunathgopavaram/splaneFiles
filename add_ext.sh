#!/bin/bash

branch_name=$(git symbolic-ref --short HEAD)
for file in *.py; do
  filename="${file%.*}"  # Remove the extension
  extension="${file##*.}"  # Extract the extension
  new_filename="${filename%_$branch_name}"  # Remove existing branch name, if any
  mv -f "$file" "${new_filename}_$branch_name.$extension" >/dev/null 2>&1
done


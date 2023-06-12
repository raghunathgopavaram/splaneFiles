#!/bin/bash

branch_name=$(git symbolic-ref --short HEAD)
for file in *.py; do
  if [[ $file == *"_"* ]]; then
    echo "File name already contains branch name: $file"
    exit 0
  fi

  filename="${file%.*}"  # Remove the extension
  extension="${file##*.}"  # Extract the extension
  new_filename="${filename%_$branch_name}"  # Remove existing branch name, if any
  if [[ "$branch_name" == "master" ]]; then
    exit 0
  else
    mv -f "$file" "${new_filename}_$branch_name.$extension" >/dev/null 2>&1
  fi
done


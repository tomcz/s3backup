#!/usr/bin/env bash

for src in $(grep -r -l 'Code generated by moq' --include='*.go' | grep -v 'vendor/'); do
  echo "Processing ${src} ..."
  sed 's/mocked/stubbed/g;s/mock/stub/g' "${src}" > "${src}.temp"
  mv "${src}.temp" "${src}"
done

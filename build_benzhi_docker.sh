#!/usr/bin/env bash
set -euo pipefail

image_name=${1:?image name required}
platform=${2:?platform required}

case "$platform" in
  linux/amd64|linux/arm64) ;;
  *) echo "platform must be linux/amd64 or linux/arm64" >&2; exit 2 ;;
esac

docker buildx build \
  --platform "$platform" \
  --file benzhi.Dockerfile \
  --tag "${image_name}:latest" \
  --load \
  .

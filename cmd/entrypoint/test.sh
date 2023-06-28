#! /bin/bash

export TEKTON_RESOURCE_NAME=test-step
export OUT_FILE=./tmp/attestation.json


go build .
mkdir -p ./tmp
./entrypoint -post_file ./tmp/.out -termination_path ./tmp/term -entrypoint 'echo "hello world"'

cat ./tmp/attestation.json | jq -r .payload | base64 -d | jq
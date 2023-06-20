#!/bin/bash

export TEKTON_RESOURCE_NAME=test
./entrypoint -post_file .out -termination_path ./term -entrypoint echo hello
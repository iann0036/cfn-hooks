#!/bin/bash

pip3 install -t $(pwd) toml

cfn submit --set-default --region ap-southeast-2

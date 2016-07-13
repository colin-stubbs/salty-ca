#!/bin/bash

ETC_DIR="`pwd`/etc"

salt-call --config-dir=${ETC_DIR} --local state.highstate -l debug

# EOF


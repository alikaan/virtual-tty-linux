#!/bin/bash
set +x	# enable/disable debug

sudo picocom -b 115200 -l -r /dev/vtty0
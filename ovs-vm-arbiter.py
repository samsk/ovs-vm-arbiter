#!/usr/bin/env python3
# Launcher: run pyzip at fixed install path
import os
import sys

zip_path = "/usr/local/lib/ovs-vm-arbiter.zip"
if not os.path.isfile(zip_path):
    sys.exit(f"ovs-vm-arbiter: zip not found: {zip_path}")

os.execv(sys.executable, [sys.executable, zip_path] + sys.argv[1:])

#!/usr/bin/env python2
#coding: utf-8

from pyroute2 import netns
import subprocess, shlex, sys

def exec_ns(ns_name, cmd):
    netns.setns(ns_name)
    subprocess.Popen(cmd)
    
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Format: netns.py NS cmd")
        sys.exit(1)

    exec_ns(sys.argv[1], sys.argv[2:])
    

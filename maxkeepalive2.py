#!/usr/bin/env python3
"""
keepalive.py — Hardened Python wrapper for C services
"""

import subprocess
import time
import os
import sys
import signal

BINARY     = "./vuln_service"
SOURCE     = "./vuln_service.c"
MAX_CRASHES = 10 

# Hardened compilation flags for production-grade security
COMPILE_CMD = [
    "gcc", SOURCE, "-o", BINARY,
    "-O2",                       # Basic optimization level
    "-fstack-protector-all",     # Stack canary protection for all functions
    "-D_FORTIFY_SOURCE=2",       # Buffer overflow detection for standard library functions
    "-Wl,-z,relro,-z,now",       # Full RELRO (Read-only relocations) to protect the GOT
    "-fPIE", "-pie",             # Position Independent Executable for ASLR compatibility
    "-z", "noexecstack",         # Disables executable stack to prevent code injection
    "-m32",                      # Targets 32-bit architecture
]

def compile_service():
    print("[*] Compiling vuln_service.c with security hardening...")
    result = subprocess.run(COMPILE_CMD, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] Compilation failed:")
        print(result.stderr)
        sys.exit(1)
    print("[+] Compiled successfully with security hardening enabled.")

def run_keepalive():
    crash_count = 0
    proc = None

    def handle_sigint(sig, frame):
        print("\n[*] Shutting down keepalive.")
        if proc:
            proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    while crash_count < MAX_CRASHES:
        print(f"\n[*] Starting service (attempt {crash_count + 1}) ...")
        proc = subprocess.Popen([BINARY])
        proc.wait()

        if proc.returncode == 0:
            print("[*] Service exited cleanly.")
            break
        else:
            crash_count += 1
            print(f"[!] Service crashed (exit code {proc.returncode}). Restarting... ({crash_count}/{MAX_CRASHES})")
            time.sleep(1)

if __name__ == "__main__":
    if not os.path.exists(SOURCE):
        print(f"[!] Source file '{SOURCE}' not found.")
        sys.exit(1)

    compile_service()
    run_keepalive()
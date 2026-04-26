#!/usr/bin/env python3
"""
keepalive.py — Python wrapper for the vulnerable C service
FOR EDUCATIONAL USE ONLY — Cybersecurity lab environment

This script:
  1. Compiles vuln_service.c (with security mitigations disabled)
  2. Launches the compiled binary
  3. Monitors it and restarts it if it crashes (keepalive behavior)
  4. The restart behavior is intentional — it lets students retry
     their exploit without manual intervention.

Usage:
    python3 keepalive.py

Requirements:
    - gcc installed
    - vuln_service.c in the same directory
    - 32-bit libs: sudo apt install gcc-multilib
"""

import subprocess
import time
import os
import sys
import signal

BINARY     = "./vuln_service"
SOURCE     = "./vuln_service.c"
PORT       = 9999
MAX_CRASHES = 10   # stop restarting after this many crashes (lab safety)

# -- Compilation flags ----------------------------------------------------------
# -fno-stack-protector  : disables stack canary (SSP)
# -z execstack          : marks stack executable (allows shellcode on stack)
# -no-pie               : fixed base address (predictable addresses for ROP/ret2win)
# -m32                  : 32-bit binary (simpler calling convention for teaching)
# ------------------------------------------------------------------------------

##### LAB SECURE #####
# COMPILE_CMD = [
#     "gcc", SOURCE, "-o", BINARY,
#     "-fstack-protector-all",
#     "-z", "execstack",
#     "-fPIE", "-pie",
#     "-D_FORTIFY_SOURCE=2",
#     "-02",
#     "-fsanitize=address",
#     "-m32",
# ]

########### INSANE SECURITY ##########
# Production-Hardened Flags
COMPILE_CMD = [
    "gcc", SOURCE, "-o", BINARY,
    "-O2",
    "-fstack-protector-all",
    "-D_FORTIFY_SOURCE=2",
    "-Wl,-z,relro,-z,now",  # Full RELRO
    "-fPIE", "-pie",
    "-z", "noexecstack",
    "-m32"
]

def compile_service():
    print("[*] Compiling vuln_service.c ...")
    result = subprocess.run(COMPILE_CMD, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] Compilation failed:")
        print(result.stderr)
        sys.exit(1)
    print("[+] Compiled successfully.")
    print(f"[+] Security mitigations disabled: stack canary=OFF, NX=OFF, PIE=OFF")

def disable_aslr():
    """
    Disable ASLR for the lab so stack addresses are deterministic.
    Requires root. Students can also run:
        echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
    """
    try:
        with open("/proc/sys/kernel/randomize_va_space", "w") as f:
            f.write("0\n")
        print("[+] ASLR disabled (randomize_va_space = 0)")
    except PermissionError:
        print("[!] Could not disable ASLR — run as root, or manually:")
        print("    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")

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
        print(f"\n[*] Starting vuln_service (attempt {crash_count + 1}) ...")
        proc = subprocess.Popen([BINARY])

        proc.wait()  # block until the process exits (crash or clean)

        exit_code = proc.returncode
        if exit_code == 0:
            print("[*] Service exited cleanly.")
            break
        else:
            crash_count += 1
            print(f"[!] Service crashed (exit code {exit_code}). "
                  f"Restarting in 1 second... ({crash_count}/{MAX_CRASHES})")
            time.sleep(1)

    if crash_count >= MAX_CRASHES:
        print(f"[!] Reached max crash limit ({MAX_CRASHES}). Stopping keepalive.")

if __name__ == "__main__":
    if not os.path.exists(SOURCE):
        print(f"[!] Source file '{SOURCE}' not found. Place it in the same directory.")
        sys.exit(1)

    compile_service()
    disable_aslr()
    run_keepalive()

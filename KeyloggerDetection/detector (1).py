from bcc import BPF
import time
import os
import sys
from datetime import datetime

# Allowed system processes that legitimately read from input devices
# We allow typical display servers and input managers
ALLOWLIST = [
    "Xorg", 
    "wayland", 
    "systemd-logind", 
    "acpid", 
    "gnome-shell",
    "kworker",
    "upowerd",
    "thermald",
    b"Xorg",
    b"wayland",
    b"systemd-logind"
]

def load_bpf_program():
    try:
        with open("ebpf_probe.c", "r") as f:
            bpf_text = f.read()
    except FileNotFoundError:
        print("Error: ebpf_probe.c not found in the current directory.")
        sys.exit(1)

    print("Compiling eBPF program... This may take a few seconds.")
    try:
        b = BPF(text=bpf_text)
        return b
    except Exception as e:
        print("--------------------------------------------------")
        print("Failed to load BPF program!")
        print("1. Are you running this script with sudo/root privileges?")
        print("2. Do you have linux-headers installed for your kernel?")
        print("--------------------------------------------------")
        print(f"Error details: {e}")
        sys.exit(1)

def main():
    b = load_bpf_program()
    print("\n✅ eBPF program loaded successfully into the kernel!")
    print("🛡️  Monitoring for suspicious keylogger activities... (Press Ctrl+C to stop)")
    print("-" * 80)
    print(f"{'TIME':<12} | {'PID':<8} | {'PROCESS NAME':<20} | {'TARGET FILE':<15} | {'STATUS'}")
    print("-" * 80)

    # Callback function to handle events from the kernel
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        
        # Decode strings from C struct
        try:
            comm = event.comm.decode('utf-8', 'replace')
            filename = event.filename.decode('utf-8', 'replace')
        except Exception:
            comm = str(event.comm)
            filename = str(event.filename)
            
        current_time = datetime.now().strftime("%H:%M:%S")

        # Basic exact match or startswith for allowlist
        is_allowed = False
        for allowed in ALLOWLIST:
            if type(allowed) == str and comm.startswith(allowed):
                is_allowed = True
                break
                
        if not is_allowed:
            print(f"\033[91m{current_time:<12} | {event.pid:<8} | {comm:<20} | {filename:<15} | [🚨 POTENTIAL KEYLOGGER]\033[0m")
        else:
            # Uncomment the next line if you want to see allowed/legitimate processes too
            # print(f"\033[92m{current_time:<12} | {event.pid:<8} | {comm:<20} | {filename:<15} | [✅ ALLOWED]\033[0m")
            pass

    # Open the performance ring buffer
    b["events"].open_perf_buffer(print_event)

    # Polling loop
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nDetaching eBPF program and exiting...")
            sys.exit(0)

if __name__ == "__main__":
    main()

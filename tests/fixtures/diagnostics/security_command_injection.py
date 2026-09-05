import subprocess

def ping_host(host):
    subprocess.run(f"ping -c 1 {host}", shell=True)

#!/usr/bin/env python3
"""Run a command on the CI server (172.16.10.244) with this repo synced to ~/packout.
Usage: python scripts/rtest-remote.py [--no-sync] <shell command...>
Env: PH/PU/PP host/user/password; PT timeout seconds (default 1800).
"""
import io, os, subprocess, sys, tarfile, paramiko

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = os.environ.get("PH", "172.16.10.244")
USER = os.environ.get("PU", "yekun")
PASS = os.environ.get("PP", "song2026")
DEST = os.environ.get("PD", "~/packout")

args = sys.argv[1:]
do_sync = True
if args and args[0] == "--no-sync":
    do_sync = False
    args = args[1:]
cmd = " ".join(args) or "go test ./..."
if not cmd.startswith("cd "):
    cmd = ("cd %s && export PATH=$HOME/tools/go/bin:$PATH GOCACHE=$HOME/.cache/go-build "
           "GOFLAGS=-mod=mod GOPROXY=https://goproxy.cn,direct && ") % DEST + cmd

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, 22, USER, PASS, timeout=30, allow_agent=False, look_for_keys=False)
try:
    if do_sync:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(ROOT, arcname=".", filter=lambda ti: None if any(
                s in ti.name for s in ("/.git", "/build", "__pycache__", ".exe")) else ti)
        buf.seek(0)
        sftp = client.open_sftp()
        tgz = "packout-sync-%d.tgz" % os.getpid()
        with sftp.file(tgz, "wb") as f:
            f.write(buf.read())
        sftp.close()
        _, out, err = client.exec_command("rm -rf %s && mkdir -p %s && tar xzf ~/%s -C %s && rm -f ~/%s" % (DEST, DEST, tgz, DEST, tgz))
        out.channel.recv_exit_status()
    _, so, se = client.exec_command(cmd, get_pty=False, timeout=int(os.environ.get("PT", "1800")))
    data = so.read()
    sys.stdout.write(data.decode(errors="replace"))
    sys.stderr.write(se.read().decode(errors="replace"))
    raise SystemExit(so.channel.recv_exit_status())
except paramiko.SSHException as e:
    print("ssh: %s" % e, file=sys.stderr)
    raise SystemExit(90)

#!/usr/bin/env python3
"""SkidSploit CLI — talk to the injected dylib."""

import socket, struct, sys, time, os, readline, glob
from pathlib import Path

SOCK_DIR = Path("/tmp/skidsploit")
TIMEOUT  = 5
CMD_STATUS = b"\x00"
CMD_SOURCE = b"\x02"

R = "\033[0m"
B = "\033[1m"
G = "\033[32m"
Y = "\033[33m"
RED = "\033[31m"
C = "\033[36m"
DIM = "\033[2m"

def ok(s):   print(f"  {G}✓{R} {s}")
def bad(s):  print(f"  {RED}✗{R} {s}")
def info(s): print(f"  {C}>{R} {s}")
def dim(s):  print(f"  {DIM}{s}{R}")

def find_sock():
    if not SOCK_DIR.exists():
        return None
    socks = sorted(SOCK_DIR.glob("*.sock"), key=lambda p: p.stat().st_mtime, reverse=True)
    for s in socks:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
                c.settimeout(1)
                c.connect(str(s))
            return str(s)
        except OSError:
            s.unlink(missing_ok=True)
    return None

def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def send_cmd(payload):
    path = find_sock()
    if not path:
        return None, "no socket found — is Roblox running with SkidSploit?"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect(path)
            s.sendall(struct.pack(">Q", len(payload)) + payload)
            raw = recv_exact(s, 8)
            if not raw:
                return None, "no response"
            rlen = struct.unpack(">Q", raw)[0]
            data = recv_exact(s, rlen)
            if not data:
                return None, "connection closed"
            return data.decode("utf-8", errors="replace"), None
    except ConnectionRefusedError:
        return None, "connection refused"
    except TimeoutError:
        return None, "timed out"
    except OSError as e:
        return None, str(e)

def cmd_status():
    resp, err = send_cmd(CMD_STATUS)
    if err:
        bad(err)
        return False
    ok(resp)
    sock = find_sock()
    dim(f"socket: {sock}")
    return "ready=true" in resp

def cmd_exec(source):
    resp, err = send_cmd(CMD_SOURCE + source.encode("utf-8"))
    if err:
        bad(err)
        return
    if resp == "ok":
        ok("sent")
    else:
        bad(resp)

def cmd_file(path):
    p = Path(path)
    if not p.exists():
        bad(f"file not found: {path}")
        return
    source = p.read_text("utf-8")
    info(f"sending {p.name} ({len(source)} bytes)")
    cmd_exec(source)

def cmd_watch(path):
    p = Path(path)
    if not p.exists():
        bad(f"file not found: {path}")
        return
    info(f"watching {p.name} — save to execute, Ctrl-C to stop")
    last = 0.0
    while True:
        try:
            mt = p.stat().st_mtime
            if mt != last:
                last = mt
                print()
                info(f"{p.name} changed")
                cmd_file(str(p))
            time.sleep(0.3)
        except KeyboardInterrupt:
            print()
            break

def cmd_log():
    home = os.environ.get("HOME", "")
    log = Path(home) / "Documents" / "SkidSploit" / "skidsploit.log"
    if not log.exists():
        bad("no log file")
        return
    print(log.read_text())

def cmd_wait(timeout=30):
    info(f"waiting for game (up to {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        resp, err = send_cmd(CMD_STATUS)
        if resp and "ready=true" in resp:
            ok("ready!")
            return True
        time.sleep(1)
        sys.stdout.write(".")
        sys.stdout.flush()
    print()
    bad("timed out")
    return False

REPL_HELP = f"""
  {B}Commands{R}
    :s  :status     connection status
    :l  :log        show dylib log
    :w  :wait       wait until game loads
    :f  <path>      execute a .lua file
    :h  :help       this help
    :q  :quit       exit

  {B}Multi-line{R}
    Type lines, then {B};;{R} on its own line to execute.
    Or just type a single line and press Enter.
"""

def repl():
    sock = find_sock()
    print(f"\n  {B}SkidSploit{R}  {DIM}REPL{R}")
    if sock:
        ok(f"socket: {sock}")
    else:
        bad("no socket — is Roblox running?")
    print(f"  type {B}:h{R} for help\n")

    hist_dir = Path.home() / ".skidsploit"
    hist_dir.mkdir(exist_ok=True)
    hist_file = hist_dir / "history"
    try:
        readline.read_history_file(str(hist_file))
    except FileNotFoundError:
        pass
    readline.set_history_length(500)

    buf = []
    while True:
        prompt = f"{G}>>{R} " if not buf else f"{DIM}..{R} "
        try:
            line = input(prompt)
        except (KeyboardInterrupt, EOFError):
            if buf:
                buf.clear()
                print(f"  {Y}cancelled{R}")
                continue
            print()
            break

        stripped = line.strip()

        if not buf:
            if stripped in (":q", ":quit"):
                break
            if stripped in (":h", ":help"):
                print(REPL_HELP)
                continue
            if stripped in (":s", ":status"):
                cmd_status()
                continue
            if stripped in (":l", ":log"):
                cmd_log()
                continue
            if stripped in (":w", ":wait"):
                cmd_wait()
                continue
            if stripped.startswith(":f "):
                cmd_file(stripped[3:].strip())
                continue

        if stripped == ";;":
            if buf:
                cmd_exec("\n".join(buf))
                buf.clear()
            continue

        buf.append(line)

        if len(buf) == 1 and stripped:
            cmd_exec(buf.pop())

    try:
        readline.write_history_file(str(hist_file))
    except OSError:
        pass

USAGE = f"""
  {B}SkidSploit CLI{R}

  {B}Usage:{R}
    client.py                          interactive REPL
    client.py exec <code>              execute lua code
    client.py file <path>              execute a .lua file
    client.py watch <path>             re-run on file save
    client.py status                   check connection
    client.py log                      show dylib log
    client.py wait                     wait until game loads
"""

def main():
    args = sys.argv[1:]

    if not args:
        repl()
        return

    cmd = args[0].lstrip("-")

    if cmd == "exec" and len(args) >= 2:
        cmd_exec(" ".join(args[1:]))
    elif cmd == "file" and len(args) >= 2:
        cmd_file(args[1])
    elif cmd == "watch" and len(args) >= 2:
        cmd_watch(args[1])
    elif cmd == "status":
        cmd_status()
    elif cmd == "log":
        cmd_log()
    elif cmd == "wait":
        cmd_wait(int(args[1]) if len(args) > 1 else 30)
    else:
        print(USAGE)

if __name__ == "__main__":
    main()

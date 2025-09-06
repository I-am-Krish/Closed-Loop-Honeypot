# honeypot/commands.py
# Realistic command emulator for closed-loop honeypot.
# Returns either:
#   - dict: {"output": "<string>", "cwd": "<path>"} OR
#   - None for exit/close signals

import os
import time
import random
import hashlib
from collections import deque
from datetime import datetime, timedelta

# ---------------------------
# Fake filesystem & contents
# ---------------------------
# Keys are absolute paths. Directories map to list of names within them.
fake_fs = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "proc", "root", "sbin", "srv", "tmp", "usr", "var"],
    "/home": ["root", "admin"],
    "/home/root": ["readme.txt", "id_rsa", "notes.txt"],
    "/home/admin": ["important.txt"],
    "/etc": ["passwd", "shadow", "hosts", "hostname", "ssh"],
    "/etc/ssh": ["sshd_config", "ssh_config"],
    "/var": ["log", "www"],
    "/var/log": ["auth.log", "syslog", "boot.log"],
    "/usr": ["bin"],
    "/usr/bin": ["python3", "bash", "ls"],
    "/root": ["wallet.dat", "secret.env"],
    "/tmp": [],
    "/srv": ["www"],
    "/srv/www": ["index.html"],
}

# file_contents keyed by filename (not by full path) to keep simple
file_contents = {
    "readme.txt": "Welcome to Ubuntu 20.04 LTS.\nThis server is for internal use.\n",
    "notes.txt": "TODO:\n - rotate keys\n - update backups\n",
    "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE_KEY_MATERIAL\n-----END OPENSSH PRIVATE KEY-----\n",
    "important.txt": "Company internal notes: ... (fake)\n",
    "passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\n",
    "shadow": "root:$6$saltsalt$hashedpassword:19000:0:99999:7:::\n",
    "hosts": "127.0.0.1 localhost\n192.168.1.10 server01\n",
    "hostname": "server01\n",
    "sshd_config": "# Fake sshd config\nPermitRootLogin yes\n",
    "auth.log": "Sep  5 12:00:00 server01 sshd[123]: Accepted password for root from 192.168.1.55 port 51234 ssh2\n",
    "syslog": "Sep  5 12:10:05 server01 CRON[456]: (root) CMD (run-parts /etc/cron.hourly)\n",
    "index.html": "<html><body><h1>It works</h1></body></html>\n",
    "secret.env": "DB_PASSWORD=fake_password_123\nAPI_KEY=FAKE-1234567890\n",
    "wallet.dat": "(binary blob)\n",
    "boot.log": "Boot process log ....\n",
}

# ---------------------------
# Fake users & groups
# ---------------------------
fake_users = {
    "root": {"uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"},
    "admin": {"uid": 1000, "gid": 1000, "home": "/home/admin", "shell": "/bin/bash"},
}

fake_groups = {
    0: "root",
    1000: "admin",
}

# ---------------------------
# History
# ---------------------------
HISTSIZE = 200
history = deque(maxlen=HISTSIZE)

# ---------------------------
# Helper utilities
# ---------------------------
def now_str():
    return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")  # for `date`-like outputs

def resolve_path(cwd, path):
    """Resolve a given path (absolute or relative) into an absolute path string."""
    if not path:
        return cwd
    if path.startswith("/"):
        candidate = os.path.normpath(path)
    else:
        candidate = os.path.normpath(os.path.join(cwd, path))
    # normalize root
    if candidate == ".":
        candidate = "/"
    return candidate

def exists_in_fs(path):
    """Return whether path is a known directory or a file (filename within dir)."""
    path = os.path.normpath(path)
    if path in fake_fs:
        return ("dir", True)
    # split into dir + name
    d, name = os.path.split(path)
    if d == "":
        d = "/"
    if d in fake_fs and name in fake_fs[d]:
        return ("file", True)
    return (None, False)

def file_owner_and_meta(name):
    """Return owner, group, size, mtime for a fake file name."""
    # owner by heuristic: id_rsa/wallet => root, else admin or root randomly
    owner = "root" if name in ("id_rsa", "wallet.dat", "shadow") else "admin" if name == "important.txt" else "root"
    uid = fake_users.get(owner, {}).get("uid", 1000)
    gid = fake_users.get(owner, {}).get("gid", 1000)
    # size approximated by length of content if exists else random
    content = file_contents.get(name, "")
    size = len(content.encode("utf-8"))
    if size == 0:
        size = random.randint(20, 2048)
    # mtime deterministic-ish from name hash
    h = int(hashlib.sha1(name.encode()).hexdigest(), 16)
    days_ago = (h % 200)  # up to ~200 days old
    mtime = datetime.now() - timedelta(days=days_ago, hours=(h % 24))
    return owner, uid, gid, size, mtime

def fmt_mtime(dt):
    return dt.strftime("%b %d %H:%M")

def perms_for(name):
    # simple permissions: sensitive files stricter
    if name in ("id_rsa", "shadow"):
        return "-rw-------"
    if name in ("passwd", "sshd_config"):
        return "-rw-r--r--"
    if name.endswith(".sh") or name in ("python3", "bash"):
        return "-rwxr-xr-x"
    return "-rw-r--r--"

# ---------------------------
# Main command handler
# ---------------------------
def handle_command(command, session):
    """
    Runs a fake command in the honeypot.
    Input:
      - command: raw user input string
      - session: dict with keys: user, host, cwd
    Returns:
      - dict {"output": str, "cwd": newcwd} OR
      - None for exit
    """
    cwd = session.get("cwd", "/home/root")
    user = session.get("user", "root")
    host = session.get("host", "server01")

    if not command:
        return {"output": "", "cwd": cwd}

    parts = command.strip().split()
    cmd = parts[0]
    args = parts[1:]

    # record to history
    history.append(command)

    # ------- navigation -------
    if cmd == "pwd":
        return {"output": cwd + "\n", "cwd": cwd}

    if cmd == "cd":
        target = args[0] if args else ""
        if target == "" or target == "~":
            new_cwd = fake_users.get(user, {}).get("home", "/home/root")
            return {"output": "", "cwd": new_cwd}
        newpath = resolve_path(cwd, target)
        # allow .. traversal to root
        if newpath in fake_fs:
            return {"output": "", "cwd": newpath}
        # if newpath is a file's dir and name given, reject
        parent, name = os.path.split(newpath)
        if parent in fake_fs and name in fake_fs.get(parent, []):
            return {"output": f"bash: cd: {target}: Not a directory\n", "cwd": cwd}
        return {"output": f"bash: cd: {target}: No such file or directory\n", "cwd": cwd}

    # ------- ls (support -l) -------
    if cmd == "ls":
        long = False
        target = ""
        for a in args:
            if a == "-l":
                long = True
            elif a.startswith("-"):
                # ignore other flags
                continue
            else:
                target = a
        # determine listing directory
        list_dir = resolve_path(cwd, target) if target else cwd
        if list_dir not in fake_fs:
            return {"output": f"ls: cannot access '{target}': No such file or directory\n", "cwd": cwd}
        items = fake_fs.get(list_dir, [])
        if not long:
            return {"output": "  ".join(items) + ("\n" if items else "\n"), "cwd": cwd}
        # build long listing
        lines = []
        for name in items:
            # treat directories vs files heuristically
            full = os.path.join(list_dir, name)
            if full in fake_fs:
                # dir
                perms = "drwxr-xr-x"
                links = 2
                owner = "root"
                group = fake_groups.get(0, "root")
                size = 4096
                mtime = datetime.now() - timedelta(days=random.randint(1, 90))
                lines.append(f"{perms} {links} {owner} {group} {size:>6} {fmt_mtime(mtime)} {name}")
            else:
                perms = perms_for(name)
                owner, uid, gid, size, mtime = file_owner_and_meta(name)
                group = fake_groups.get(gid, str(gid))
                links = 1
                lines.append(f"{perms} {links} {owner} {group} {size:>6} {fmt_mtime(mtime)} {name}")
        return {"output": "\n".join(lines) + "\n", "cwd": cwd}

    # ------- cat (support absolute and relative) -------
    if cmd == "cat":
        if not args:
            return {"output": "cat: missing file operand\n", "cwd": cwd}
        target = args[0]
        path = resolve_path(cwd, target)
        # if absolute path or relative path to a file inside dir
        typ, exists = exists_in_fs(path)
        if exists and typ == "file":
            _, name = os.path.split(path)
            content = file_contents.get(name, "(binary content)\n")
            return {"output": content, "cwd": cwd}
        # also check if user asked for /etc/passwd without specifying absolute path
        # already handled by resolve_path
        return {"output": f"cat: {target}: No such file or directory\n", "cwd": cwd}

    # ------- head/tail -------
    if cmd == "head" or cmd == "tail":
        if not args:
            return {"output": f"{cmd}: missing file operand\n", "cwd": cwd}
        path = resolve_path(cwd, args[0])
        typ, exists = exists_in_fs(path)
        if not exists or typ != "file":
            return {"output": f"{cmd}: {args[0]}: No such file or directory\n", "cwd": cwd}
        _, name = os.path.split(path)
        content = file_contents.get(name, "(binary content)\n").splitlines()
        count = 10
        if cmd == "head":
            out = "\n".join(content[:count]) + ("\n" if content else "\n")
        else:
            out = "\n".join(content[-count:]) + ("\n" if content else "\n")
        return {"output": out, "cwd": cwd}

    # ------- echo -------
    if cmd == "echo":
        return {"output": " ".join(args) + "\n", "cwd": cwd}

    # ------- touch (only simulate) -------
    if cmd == "touch":
        if not args:
            return {"output": "touch: missing file operand\n", "cwd": cwd}
        target = resolve_path(cwd, args[0])
        parent, name = os.path.split(target)
        if parent not in fake_fs:
            return {"output": f"touch: cannot touch '{args[0]}': No such file or directory\n", "cwd": cwd}
        # add to fake fs if not exists
        if name not in fake_fs[parent]:
            fake_fs[parent].append(name)
            file_contents[name] = ""  # empty file
        return {"output": "", "cwd": cwd}

    # ------- mkdir -------
    if cmd == "mkdir":
        if not args:
            return {"output": "mkdir: missing operand\n", "cwd": cwd}
        target = resolve_path(cwd, args[0])
        if target in fake_fs:
            return {"output": f"mkdir: cannot create directory '{args[0]}': File exists\n", "cwd": cwd}
        # simulate create
        fake_fs[target] = []
        parent = os.path.dirname(target)
        base = os.path.basename(target)
        if parent in fake_fs and base not in fake_fs[parent]:
            fake_fs[parent].append(base)
        return {"output": "", "cwd": cwd}

    # ------- rm (simulate) -------
    if cmd == "rm":
        if not args:
            return {"output": "rm: missing operand\n", "cwd": cwd}
        target = resolve_path(cwd, args[0])
        parent, name = os.path.split(target)
        if parent not in fake_fs or name not in fake_fs[parent]:
            return {"output": f"rm: cannot remove '{args[0]}': No such file or directory\n", "cwd": cwd}
        # do not allow removing sensitive files like passwd/shadow
        if name in ("passwd", "shadow", "id_rsa", "wallet.dat"):
            return {"output": f"rm: cannot remove '{args[0]}': Operation not permitted\n", "cwd": cwd}
        fake_fs[parent].remove(name)
        if name in file_contents:
            del file_contents[name]
        return {"output": "", "cwd": cwd}

    # ------- whoami / id / groups -------
    if cmd == "whoami":
        return {"output": user + "\n", "cwd": cwd}
    if cmd == "id":
        info = fake_users.get(user, {})
        uid = info.get("uid", 1000)
        gid = info.get("gid", 1000)
        groups = [fake_groups.get(gid, str(gid))]
        return {"output": f"uid={uid}({user}) gid={gid}({fake_groups.get(gid)}) groups={','.join(groups)}\n", "cwd": cwd}
    if cmd == "groups":
        info = fake_users.get(user, {})
        gid = info.get("gid", 1000)
        return {"output": fake_groups.get(gid, "users") + "\n", "cwd": cwd}

    # ------- uname / date / uptime -------
    if cmd == "uname":
        return {"output": f"Linux {host} 5.15.0-91-generic #99-Ubuntu SMP x86_64 GNU/Linux\n", "cwd": cwd}
    if cmd == "date":
        return {"output": datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y\n"), "cwd": cwd}
    if cmd == "uptime":
        # simulated uptime 1-30 days
        days = random.randint(0, 30)
        hours = random.randint(0, 23)
        mins = random.randint(0, 59)
        return {"output": f" {hours:02d}:{mins:02d} up {days} days,  {random.randint(1,10)} users,  load average: 0.00, 0.01, 0.05\n", "cwd": cwd}

    # ------- ps (fake processes) -------
    if cmd == "ps":
        lines = [
            "  PID TTY          TIME CMD",
            "    1 ?        00:00:01 init",
            "  233 ?        00:00:00 sshd",
            " 1024 ?        00:00:04 nginx",
            " 2020 pts/0    00:00:00 bash",
            " 3030 pts/0    00:00:00 python3",
        ]
        return {"output": "\n".join(lines) + "\n", "cwd": cwd}

    # ------- ss / ifconfig / ip -------
    if cmd in ("ss", "netstat"):
        return {"output": "LISTEN 0      128         *:22       *:*    \n", "cwd": cwd}
    if cmd in ("ifconfig", "ip"):
        return {"output": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n    inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255\n", "cwd": cwd}

    # ------- sudo -------
    if cmd == "sudo":
        # mimic common sudo error without password prompt
        return {"output": f"{user} is not in the sudoers file.  This incident will be reported.\n", "cwd": cwd}

    # ------- history -------
    if cmd == "history":
        out = "\n".join(f"{i+1}  {h}" for i, h in enumerate(history))
        return {"output": out + ("\n" if out else "\n"), "cwd": cwd}

    # ------- exit / logout / quit -------
    if cmd in ("exit", "logout", "quit"):
        return None

    # ------- default fallback -------
    return {"output": f"bash: {cmd}: command not found\n", "cwd": cwd}
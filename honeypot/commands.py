import random
from collections import deque
from datetime import datetime

# ---------------------------
# Fake filesystem & contents
# ---------------------------
fake_fs = {
    "/": ["home", "etc", "var", "tmp", "usr", "root"],
    "/home": ["root", "admin"],
    "/home/root": ["readme.txt", "id_rsa", "notes.txt"],
    "/etc": ["passwd", "shadow", "hosts"],
    "/var": ["log"],
    "/var/log": ["auth.log", "syslog"],
    "/root": ["wallet.dat", "secret.env"]
}

file_contents = {
    "readme.txt": "Welcome to Ubuntu 20.04 LTS.\n",
    "notes.txt": "TODO: Change root password!\n",
    "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nfakefakefake\n-----END OPENSSH PRIVATE KEY-----\n",
    "passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n",
    "shadow": "root:$6$saltsalt$hashedpassword:19000:0:99999:7:::\n",
    "auth.log": "Sep  5 12:00:00 server01 sshd[123]: Accepted password for root from 192.168.1.55 port 51234 ssh2\n",
    "syslog": "Sep  5 12:10:05 server01 CRON[456]: (root) CMD (run-parts /etc/cron.hourly)\n",
    "secret.env": "DB_PASSWORD=fake_password_123\nAPI_KEY=FAKE-1234567890\n",
    "wallet.dat": "(binary blob)\n"
}

# ---------------------------
# History and Logging
# ---------------------------
HISTSIZE = 100
history = deque(maxlen=HISTSIZE)

def log_command(session, cmd):
    history.append(cmd)
    return f"[{datetime.now()}] {session['user']}@{session['host']}:{session['cwd']}$ {cmd}"

# ---------------------------
# Fake command execution
# ---------------------------
def handle_command(command, session):
    cwd = session.get("cwd", "/home/root")
    parts = command.strip().split()
    if not parts:
        return ""

    cmd = parts[0]

    # --- Navigation ---
    if cmd == "ls":
        return "  ".join(fake_fs.get(cwd, [])) + "\n"

    if cmd == "cd":
        if len(parts) < 2:
            session["cwd"] = "/home/root"
        else:
            newdir = parts[1]
            if newdir.startswith("/"):
                path = newdir
            else:
                path = cwd.rstrip("/") + "/" + newdir
            if path in fake_fs:
                session["cwd"] = path
            else:
                return f"bash: cd: {newdir}: No such file or directory\n"
        return ""

    if cmd == "pwd":
        return cwd + "\n"

    # --- File access ---
    if cmd == "cat":
        if len(parts) < 2:
            return "cat: missing file operand\n"
        fname = parts[1]
        if fname in fake_fs.get(cwd, []):
            return file_contents.get(fname, "(binary content)\n")
        else:
            return f"cat: {fname}: No such file or directory\n"

    # --- System Info ---
    if cmd == "whoami":
        return session["user"] + "\n"

    if cmd == "id":
        return "uid=0(root) gid=0(root) groups=0(root)\n"

    if cmd == "uname":
        return f"Linux {session['host']} 5.15.0-91-generic x86_64 GNU/Linux\n"

    if cmd == "ps":
        return (
            "  PID TTY          TIME CMD\n"
            "    1 ?        00:00:01 init\n"
            "  233 ?        00:00:00 sshd\n"
            "  456 pts/0    00:00:00 bash\n"
            "  789 pts/0    00:00:00 ps\n"
        )

    if cmd == "df":
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   12G   35G  26% /\n"
            "tmpfs           983M     0  983M   0% /dev/shm\n"
        )

    if cmd in ["ifconfig", "ip"]:
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255\n"
            "        ether 02:42:ac:11:00:02  txqueuelen 1000  (Ethernet)\n"
        )

    # --- History ---
    if cmd == "history":
        return "\n".join(f"{i+1}  {h}" for i, h in enumerate(history)) + "\n"

    # --- Exit ---
    if cmd in ["exit", "quit", "logout"]:
        return None

    # Default
    return f"bash: {cmd}: command not found\n"
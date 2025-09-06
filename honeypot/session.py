import asyncio
import random
import uuid
from datetime import datetime
from honeypot.logger import log_event, log_command_event, log_session_summary
from honeypot.commands import handle_command


class Session:
    def __init__(self, reader, writer, config):
        self.reader = reader
        self.writer = writer
        self.config = config
        self.session_id = str(uuid.uuid4())
        self.username = None
        self.hostname = config.get("hostname", "honeypot")
        self.cwd = "/home/root"

        # 🆕 Track session metadata
        self.start_time = datetime.utcnow()
        self.commands_run = []

    async def run(self):
        banner = random.choice(
            self.config.get("banner_variants", ["SSH-2.0-OpenSSH_8.2p1"])
        )
        self.writer.write((banner + "\r\n").encode())
        await self.writer.drain()

        # Fake login
        self.writer.write(b"login: ")
        await self.writer.drain()
        username = (await self.reader.readline()).decode().strip()

        self.writer.write(b"Password: ")
        await self.writer.drain()
        password = (await self.reader.readline()).decode().strip()

        fake_users = self.config.get("fake_users", {})
        if username in fake_users and fake_users[username] == password:
            # Fake last login banner
            now = datetime.now()
            last_login_time = now.strftime("%a %b %d %H:%M:%S %Y")
            fake_ip = random.choice(["192.168.1.55", "10.0.2.15", "172.16.0.22"])
            self.writer.write(
                f"Last login: {last_login_time} from {fake_ip}\n".encode()
            )

            self.writer.write(f"Welcome to {self.hostname}!\n".encode())
            await self.writer.drain()

            log_event(self.session_id, "login_success", {"username": username})
            self.username = username
            await self.shell()
        else:
            self.writer.write(b"Login incorrect\n")
            await self.writer.drain()
            log_event(self.session_id, "login_failed", {"username": username})
            self.writer.close()

    async def shell(self):
        self.history_index = len(self.commands_run)
        input_buf = []
        cursor = 0

        while True:
            # Dynamic prompt
            prompt = f"{self.username}@{self.hostname}:{self.cwd}$ "
            self.writer.write(prompt.encode())
            await self.writer.drain()

            input_buf = []
            cursor = 0

            while True:
                char = await self.reader.read(1)
                if not char:
                    return

                c = char.decode(errors="ignore")

                # Newline = execute command
                if c in ("\n", "\r"):
                    command = "".join(input_buf)
                    self.writer.write(b"\n")
                    await self.writer.drain()
                    break

                # Backspace
                elif c in ("\b", "\x7f"):
                    if cursor > 0:
                        cursor -= 1
                        input_buf.pop(cursor)
                        self.writer.write(b"\b \b")
                        await self.writer.drain()

                # Arrow keys (escape sequences)
                elif c == "\x1b":
                    seq = await self.reader.read(2)  # e.g. [A, [B, [C, [D
                    if seq == b"[A":  # Up
                        if self.history_index > 0:
                            self.history_index -= 1
                            input_buf = list(self.commands_run[self.history_index])
                            cursor = len(input_buf)
                            self.writer.write(
                                b"\r" + prompt.encode() + "".join(input_buf).encode()
                            )
                            await self.writer.drain()
                    elif seq == b"[B":  # Down
                        if self.history_index < len(self.commands_run) - 1:
                            self.history_index += 1
                            input_buf = list(self.commands_run[self.history_index])
                        else:
                            self.history_index = len(self.commands_run)
                            input_buf = []
                        cursor = len(input_buf)
                        self.writer.write(
                            b"\r" + prompt.encode() + "".join(input_buf).encode()
                        )
                        await self.writer.drain()
                    elif seq == b"[C":  # Right
                        if cursor < len(input_buf):
                            cursor += 1
                            self.writer.write(b"\x1b[C")
                            await self.writer.drain()
                    elif seq == b"[D":  # Left
                        if cursor > 0:
                            cursor -= 1
                            self.writer.write(b"\x1b[D")
                            await self.writer.drain()

                # Regular char insert
                else:
                    input_buf.insert(cursor, c)
                    cursor += 1
                    self.writer.write(c.encode())
                    await self.writer.drain()

            # Got the command
            if not command.strip():
                continue

            result = handle_command(
                command,
                {"user": self.username, "host": self.hostname, "cwd": self.cwd},
            )

            # Exit handling
            if result is None:
                self.writer.write(b"logout\n")
                await self.writer.drain()
                break

            output = result.get("output", "")
            new_cwd = result.get("cwd", self.cwd)
            self.cwd = new_cwd

            # Track + log
            self.commands_run.append(command)
            log_command_event(
                self.session_id,
                self.username,
                self.hostname,
                self.cwd,
                command,
                output,
            )

            # Print output
            await asyncio.sleep(random.uniform(0.05, 0.2))  # tiny delay for realism
            if output:
                self.writer.write(output.encode())
                if not output.endswith("\n"):
                    self.writer.write(b"\n")
                await self.writer.drain()

        # Disconnect handling
        log_event(self.session_id, "disconnect", {})
        end_time = datetime.utcnow()
        log_session_summary(
            self.session_id,
            self.username,
            self.hostname,
            self.start_time,
            end_time,
            self.commands_run,
        )
        self.writer.close()
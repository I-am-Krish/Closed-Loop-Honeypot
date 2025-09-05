import asyncio
import random
import uuid
from honeypot.logger import log_event
from honeypot.commands import handle_command, log_command
from datetime import datetime
from honeypot.logger import log_event, log_command_event, log_session_summary

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
        banner = random.choice(self.config.get("banner_variants", ["SSH-2.0-OpenSSH_8.2p1"]))
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
        while True:
            # Dynamic prompt
            prompt = f"{self.username}@{self.hostname}:{self.cwd}$ "
            self.writer.write(prompt.encode())
            await self.writer.drain()

            data = await self.reader.readline()
            if not data:
                break
            command = data.decode().strip()

            output = handle_command(command, {
                 "user": self.username,
                 "host": self.hostname,
                 "cwd": self.cwd
                 })
            
            # keep track of commands
            self.commands_run.append(command)

            # log with context
            log_command_event(
                self.session_id,
                self.username,
                self.hostname,
                self.cwd,
                command,
                output if output else ""
            )

            # Log command with output + context
            from honeypot.logger import log_command_event
            log_command_event(
                self.session_id,
                self.username,
                self.hostname,
                self.cwd,
                command,
                output if output else ""
                )

            if output is None:  # exit/quit/logout
                self.writer.write(b"logout\n")
                await self.writer.drain()
                break
            else:
                await asyncio.sleep(random.uniform(0.1, 0.3))  # delay for realism
                if output:
                    self.writer.write(output.encode())
                    await self.writer.drain()

        log_event(self.session_id, "disconnect", {})
        end_time = datetime.utcnow()

        # 🆕 write session summary
        log_session_summary(
            self.session_id,
            self.username,
            self.hostname,
            self.start_time,
            end_time,
            self.commands_run
        )

        self.writer.close()
import asyncio
import random
import uuid
import yaml
from honeypot.logger import log_event

class Session:
    def __init__(self, reader, writer, config):
        self.reader = reader
        self.writer = writer
        self.config = config
        self.session_id = str(uuid.uuid4())
        self.username = None
        self.hostname = config.get("hostname", "honeypot")

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
            self.writer.write(f"Welcome to {self.hostname}!\n$ ".encode())
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
            data = await self.reader.readline()
            if not data:
                break
            command = data.decode().strip()
            log_event(self.session_id, "command", {"input": command})

            if command in ["exit", "quit"]:
                self.writer.write(b"Bye!\n")
                await self.writer.drain()
                break
            else:
                self.writer.write(f"bash: {command}: command not found\n$ ".encode())
                await self.writer.drain()

        log_event(self.session_id, "disconnect", {})
        self.writer.close()

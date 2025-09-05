import asyncio
from honeypot.session import Session

async def handle_client(reader, writer, config):
    session = Session(reader, writer, config)
    await session.run()

async def start_server(config):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, config),
        config["listen_host"],
        config["listen_port"]
    )
    addr = server.sockets[0].getsockname()
    print(f"🚀 Honeypot listening on {addr}")
    async with server:
        await server.serve_forever()
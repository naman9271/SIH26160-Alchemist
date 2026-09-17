#!/usr/bin/env python3
"""Minimal local SMTP sink used only inside the isolated IPsec lab."""
import argparse
import asyncio

p = argparse.ArgumentParser()
p.add_argument('--host', required=True)
p.add_argument('--port', type=int, default=2525)
a = p.parse_args()

async def session(reader, writer):
    writer.write(b'220 ipsec-lab SMTP ready\r\n')
    await writer.drain()
    in_data = False
    try:
        while line := await reader.readline():
            command = line.upper()
            if in_data:
                if line == b'.\r\n':
                    in_data = False
                    writer.write(b'250 message accepted\r\n')
                continue
            if command.startswith((b'EHLO ', b'HELO ')):
                writer.write(b'250-ipsec-lab\r\n250 SIZE 4194304\r\n')
            elif command.startswith((b'MAIL FROM:', b'RCPT TO:', b'RSET')):
                writer.write(b'250 OK\r\n')
            elif command == b'DATA\r\n':
                in_data = True
                writer.write(b'354 end data with <CR><LF>.<CR><LF>\r\n')
            elif command == b'QUIT\r\n':
                writer.write(b'221 bye\r\n')
                await writer.drain()
                break
            else:
                writer.write(b'250 OK\r\n')
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()

async def main():
    server = await asyncio.start_server(session, a.host, a.port, limit=4 * 1024 * 1024)
    async with server:
        await server.serve_forever()

asyncio.run(main())

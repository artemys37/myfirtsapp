from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio, asyncssh, re

router = APIRouter()

TERM_WIDTH = 120
TERM_HEIGHT = 40

async def _ssh_terminal(websocket: WebSocket, host: str, port: int, username: str, password: str):
    conn = await asyncssh.connect(
        host, port=port, username=username, password=password,
        known_hosts=None, client_keys=None,
    )
    chan = await conn.open_session(
        term_type="xterm-256color",
        term_size=(TERM_WIDTH, TERM_HEIGHT),
    )

    async def read_loop():
        try:
            while True:
                data = await chan.read(65536)
                if data is None:
                    break
                if isinstance(data, bytes):
                    data = data.decode("utf-8", errors="replace")
                await websocket.send_text(data)
        except Exception:
            pass

    async def write_loop():
        try:
            while True:
                data = await websocket.receive_text()
                if data == "__RESIZE__":
                    continue
                chan.write(data.encode())
                await chan.drain()
        except Exception:
            pass

    await asyncio.gather(read_loop(), write_loop())
    conn.close()

async def _telnet_terminal(websocket: WebSocket, host: str, port: int):
    reader, writer = await asyncio.open_connection(host, port)

    async def read_loop():
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                await websocket.send_text(data.decode("utf-8", errors="replace"))
        except Exception:
            pass

    async def write_loop():
        try:
            while True:
                data = await websocket.receive_text()
                if data == "__RESIZE__":
                    continue
                writer.write(data.encode())
                await writer.drain()
        except Exception:
            pass

    await asyncio.gather(read_loop(), write_loop())

@router.websocket("/ws")
async def terminal(websocket: WebSocket):
    await websocket.accept()
    try:
        q = websocket.query_params
        host = q.get("host", "")
        port = int(q.get("port", "22"))
        username = q.get("username", "")
        password = q.get("password", "")
        service = q.get("service", "ssh")

        if service == "ssh":
            await _ssh_terminal(websocket, host, port, username, password)
        elif service == "telnet":
            await _telnet_terminal(websocket, host, port)
        else:
            await websocket.send_text(f"Service non supporté: {service}\r\n")
    except WebSocketDisconnect:
        pass
    except asyncssh.Error as e:
        try:
            await websocket.send_text(f"\r\n\x1b[31mErreur SSH: {e}\x1b[0m\r\n")
        except Exception:
            pass
    except (OSError, asyncio.TimeoutError) as e:
        try:
            await websocket.send_text(f"\r\n\x1b[31mErreur connexion: {e}\x1b[0m\r\n")
        except Exception:
            pass
    except Exception as e:
        try:
            await websocket.send_text(f"\r\n\x1b[31mErreur: {e}\x1b[0m\r\n")
        except Exception:
            pass

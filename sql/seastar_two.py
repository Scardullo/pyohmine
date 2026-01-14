import asyncio
import asyncpg
import logging
import random
import json
from dataclasses import dataclass

# config

DB_CONFIG = {
    "host": "192.169.1.0",
    "port": 5432,
    "user": "user2",
    "password": "password",
    "database": "seastar",
    "ssl": False,
}

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 9000

POOL_MIN = 2
POOL_MAX = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# util

async def retry(coro, retries=5, base_delay=0.5):
    for attempt in range(retries):
        try:
            return await coro()
        except Exception as e:
            delay = base_delay * (2 ** attempt) + random.random()
            logging.warning(f"Retry {attempt+1}/{retries} after error: {e}")
            await asyncio.sleep(delay)
    raise RuntimeError("Max retries exceeded")

# database

class Database:
    def __init__(self):
        self.pool: asyncpg.Pool | None = None

    async def connect(self):
        async def _connect():
            logging.info("Connecting to PostgreSQL...")
            self.pool = await asyncpg.create_pool(
                min_size=POOL_MIN,
                max_size=POOL_MAX,
                **DB_CONFIG
            )
            logging.info("PostgreSQL pool ready")

        await retry(_connect)

    # auth

    async def get_user_by_email(self, email: str):
        async with self.pool.acquire() as conn:
            return await conn.fetchrow("""
                SELECT id, first_name, last_name, email
                FROM personnel
                WHERE email = $1
            """, email)

    # personnel

    async def fetch_person(self, pid: str):
        async with self.pool.acquire() as conn:
            return await conn.fetchrow("""
                SELECT id, first_name, last_name, email, address_id
                FROM personnel
                WHERE id = $1
            """, pid)

    async def fetch_person_full(self, pid: str):
        async with self.pool.acquire() as conn:
            return await conn.fetchrow("""
                SELECT
                    p.id, p.first_name, p.last_name, p.email,
                    a.address, a.phone, a.ip_addr
                FROM personnel p
                LEFT JOIN address a ON a.id = p.address_id
                WHERE p.id = $1
            """, pid)

    async def list_personnel_paged(self, limit: int, offset: int):
        async with self.pool.acquire() as conn:
            return await conn.fetch("""
                SELECT id, first_name, last_name, email, address_id
                FROM personnel
                ORDER BY last_name
                LIMIT $1 OFFSET $2
            """, limit, offset)

    async def search_lastname(self, name: str, limit: int, offset: int):
        async with self.pool.acquire() as conn:
            return await conn.fetch("""
                SELECT id, first_name, last_name, email, address_id
                FROM personnel
                WHERE last_name ILIKE $1
                ORDER BY last_name
                LIMIT $2 OFFSET $3
            """, f"%{name}%", limit, offset)

# session

@dataclass
class ClientState:
    logged_in: bool = False
    email: str | None = None
    json_mode: bool = False


class ClientSession:
    def __init__(self, reader, writer, db: Database):
        self.reader = reader
        self.writer = writer
        self.db = db
        self.addr = writer.get_extra_info("peername")
        self.state = ClientState()

    async def send(self, msg):
        if isinstance(msg, (dict, list)):
            msg = json.dumps(msg)
        self.writer.write((str(msg) + "\n").encode())
        await self.writer.drain()

    async def handle(self):
        logging.info(f"Client connected: {self.addr}")
        await self.send("WELCOME Seastar v2 — type HELP")

        try:
            while True:
                line = await self.reader.readline()
                if not line:
                    break

                cmd = line.decode().strip()
                if not cmd:
                    continue

                logging.info(f"{self.addr} -> {cmd}")
                if not await self.process_command(cmd):
                    break

        except Exception as e:
            logging.error(f"Client error {self.addr}: {e}")

        finally:
            self.writer.close()
            await self.writer.wait_closed()
            logging.info(f"Client disconnected: {self.addr}")

    # return False to close connection
    async def process_command(self, cmd: str) -> bool:
        parts = cmd.split()

        match parts:

            # basic

            case ["PING"]:
                await self.send("PONG")

            case ["HELP"]:
                await self.send([
                    "LOGIN <email>",
                    "MODE JSON|TEXT",
                    "GET_PERSON <id>",
                    "GET_PERSON_FULL <id>",
                    "SEARCH_LASTNAME <name> [limit] [offset]",
                    "LIST_PERSONNEL_PAGED <limit> <offset>",
                    "QUIT"
                ])

            case ["QUIT"]:
                await self.send("BYE")
                return False

            # session

            case ["MODE", mode]:
                if mode.upper() == "JSON":
                    self.state.json_mode = True
                    await self.send({"status": "ok", "mode": "json"})
                else:
                    self.state.json_mode = False
                    await self.send("OK TEXT MODE")

            case ["LOGIN", email]:
                user = await self.db.get_user_by_email(email)
                if not user:
                    await self.send("AUTH_FAIL")
                else:
                    self.state.logged_in = True
                    self.state.email = email
                    await self.send(f"AUTH_OK {user['first_name']}")

            # require login

            case _ if not self.state.logged_in:
                await self.send("ERR please LOGIN first")

            # data

            case ["GET_PERSON", pid]:
                person = await self.db.fetch_person(pid)
                if not person:
                    await self.send("NOT_FOUND")
                else:
                    await self.send(dict(person))

            case ["GET_PERSON_FULL", pid]:
                row = await self.db.fetch_person_full(pid)
                if not row:
                    await self.send("NOT_FOUND")
                else:
                    await self.send(dict(row))

            case ["LIST_PERSONNEL_PAGED", limit, offset]:
                rows = await self.db.list_personnel_paged(int(limit), int(offset))
                await self.send([dict(r) for r in rows])

            case ["SEARCH_LASTNAME", name]:
                rows = await self.db.search_lastname(name, 20, 0)
                await self.send([dict(r) for r in rows])

            case ["SEARCH_LASTNAME", name, limit, offset]:
                rows = await self.db.search_lastname(name, int(limit), int(offset))
                await self.send([dict(r) for r in rows])

            # unknown

            case _:
                await self.send("ERR unknown command")

        return True

# server

class NetworkServer:
    def __init__(self):
        self.db = Database()

    async def start(self):
        await self.db.connect()

        server = await asyncio.start_server(
            self.handle_client,
            SERVER_HOST,
            SERVER_PORT
        )

        addr = server.sockets[0].getsockname()
        logging.info(f"Server listening on {addr}")

        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        session = ClientSession(reader, writer, self.db)
        await session.handle()

# entry

if __name__ == "__main__":
    try:
        asyncio.run(NetworkServer().start())
    except KeyboardInterrupt:
        print("\nServer stopped.")

import asyncio
import asyncpg
import logging
import random

# config

DB_CONFIG = {
    "host": "192.168.1.0",
    "port": 5432,
    "user": "user1",
    "password": "password",
    "database": "seastar",   # <-- your DB name
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

# utilities

async def retry(coro, retries=5, base_delay=0.5):
    for attempt in range(retries):
        try:
            return await coro()
        except Exception as e:
            delay = base_delay * (2 ** attempt) + random.random()
            logging.warning(f"Retry {attempt+1}/{retries} after error: {e}")
            await asyncio.sleep(delay)
    raise RuntimeError("Max retries exceeded")

# database layer

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

    # personnel

    async def fetch_person(self, pid: str):
        async with self.pool.acquire() as conn:
            stmt = await conn.prepare("""
                SELECT id, first_name, last_name, email, address_id
                FROM personnel
                WHERE id = $1
            """)
            return await stmt.fetchrow(pid)

    async def list_personnel(self, limit=50):
        async with self.pool.acquire() as conn:
            stmt = await conn.prepare("""
                SELECT id, first_name, last_name, email, address_id
                FROM personnel
                ORDER BY last_name
                LIMIT $1
            """)
            return await stmt.fetch(limit)

    # address

    async def fetch_address(self, addr_id: str):
        async with self.pool.acquire() as conn:
            stmt = await conn.prepare("""
                SELECT id, address, phone, ip_addr
                FROM address
                WHERE id = $1
            """)
            return await stmt.fetchrow(addr_id)

    async def list_addresses(self, limit=50):
        async with self.pool.acquire() as conn:
            stmt = await conn.prepare("""
                SELECT id, address, phone, ip_addr
                FROM address
                LIMIT $1
            """)
            return await stmt.fetch(limit)

# protocol handler

class ClientSession:
    def __init__(self, reader, writer, db: Database):
        self.reader = reader
        self.writer = writer
        self.db = db
        self.addr = writer.get_extra_info("peername")

    async def send(self, msg: str):
        self.writer.write((msg + "\n").encode())
        await self.writer.drain()

    async def handle(self):
        logging.info(f"Client connected: {self.addr}")
        await self.send("WELCOME Seastar Personnel Service")

        try:
            while True:
                line = await self.reader.readline()
                if not line:
                    break

                cmd = line.decode().strip()
                if not cmd:
                    continue

                if not await self.process_command(cmd):
                    break 

        except Exception as e:
            logging.error(f"Client error {self.addr}: {e}")

        finally:
            self.writer.close()
            await self.writer.wait_closed()
            logging.info(f"Client disconnected: {self.addr}")

    async def process_command(self, cmd: str):
        parts = cmd.split()

        match parts:

            # BASIC

            case ["PING"]:
                await self.send("PONG")

            case ["QUIT"]:
                await self.send("BYE")
                return False

            # personnel

            case ["GET_PERSON", pid]:
                person = await self.db.fetch_person(pid)
                if not person:
                    await self.send("NOT_FOUND")
                else:
                    await self.send(
                        f"PERSON {person['id']} {person['first_name']} "
                        f"{person['last_name']} {person['email']} {person['address_id']}"
                    )

            case ["LIST_PERSONNEL"]:
                rows = await self.db.list_personnel()
                await self.send(f"COUNT {len(rows)}")
                for p in rows:
                    await self.send(
                        f"{p['id']} {p['first_name']} {p['last_name']} "
                        f"{p['email']} {p['address_id']}"
                    )

            # address

            case ["GET_ADDRESS", aid]:
                addr = await self.db.fetch_address(aid)
                if not addr:
                    await self.send("NOT_FOUND")
                else:
                    await self.send(
                        f"ADDRESS {addr['id']} {addr['address']} "
                        f"{addr['phone']} {addr['ip_addr']}"
                    )

            case ["LIST_ADDRESSES"]:
                rows = await self.db.list_addresses()
                await self.send(f"COUNT {len(rows)}")
                for a in rows:
                    await self.send(
                        f"{a['id']} {a['address']} {a['phone']} {a['ip_addr']}"
                    )

            # unknown

            case _:
                await self.send("ERR unknown command")

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

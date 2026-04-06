import asyncio
import asyncpg
import csv
from typing import List, Dict

# config
DB_CONFIG = {
    'user': 'user',
    'password': 'password',
    'database': 'it_inventory',
    'host': '192.168.1.2',
    'port': 5432
}

# database class
class ITInventoryDB:
    def __init__(self, config: Dict):
        self.config = config
        self.pool: asyncpg.Pool | None = None

    async def connect(self):
        if not self.pool:
            self.pool = await asyncpg.create_pool(**self.config)

    async def disconnect(self):
        if self.pool:
            await self.pool.close()

    # query functions
    async def get_all_users_with_devices(self) -> List[asyncpg.Record]:
        query = '''
            SELECT 
                u.id AS user_id,
                u.first_name,
                u.last_name,
                d.id AS device_id,
                d.device_type,
                d.ipv4,
                d.mac_address,
                l.id AS location_id,
                l.city,
                l.state,
                l.country,
                di.status
            FROM users u
            LEFT JOIN devices d ON d.user_id = u.id
            LEFT JOIN device_inventory di ON di.device_id = d.id
            LEFT JOIN locations l ON di.location_id = l.id
            ORDER BY u.id, d.id;
        '''
        async with self.pool.acquire() as conn:
            return await conn.fetch(query)

    async def get_device_counts_per_user(self) -> List[asyncpg.Record]:
        query = '''
            SELECT 
                u.id AS user_id,
                u.first_name,
                u.last_name,
                COUNT(d.id) AS device_count
            FROM users u
            LEFT JOIN devices d ON d.user_id = u.id
            GROUP BY u.id
            ORDER BY device_count DESC;
        '''
        async with self.pool.acquire() as conn:
            return await conn.fetch(query)

    async def get_device_counts_per_location(self) -> List[asyncpg.Record]:
        query = '''
            SELECT 
                l.id AS location_id,
                l.city,
                l.state,
                l.country,
                COUNT(di.device_id) AS device_count
            FROM locations l
            LEFT JOIN device_inventory di ON di.location_id = l.id
            GROUP BY l.id
            ORDER BY device_count DESC;
        '''
        async with self.pool.acquire() as conn:
            return await conn.fetch(query)

# utility functions

def export_to_csv(filename: str, records: List[asyncpg.Record]):
    if not records:
        print(f"No data to export for {filename}.")
        return

    keys = records[0].keys()
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in records:
            writer.writerow(dict(row))
    print(f"Exported {len(records)} records to {filename}.")

# main interface
async def main():
    db = ITInventoryDB(DB_CONFIG)
    await db.connect()

    while True:
        print("\n=== IT Inventory Reporting Menu ===")
        print("1. List all users with their devices")
        print("2. Device count per user")
        print("3. Device count per location")
        print("4. Exit")
        choice = input("Select an option: ").strip()

        if choice == '1':
            records = await db.get_all_users_with_devices()
            for r in records[:20]:  # Show first 20 for preview
                print(r)
            export_to_csv('users_with_devices.csv', records)

        elif choice == '2':
            records = await db.get_device_counts_per_user()
            for r in records:
                print(f"{r['first_name']} {r['last_name']}: {r['device_count']} devices")
            export_to_csv('device_counts_per_user.csv', records)

        elif choice == '3':
            records = await db.get_device_counts_per_location()
            for r in records:
                print(f"{r['city']}, {r['state']}, {r['country']}: {r['device_count']} devices")
            export_to_csv('device_counts_per_location.csv', records)

        elif choice == '4':
            break

        else:
            print("Invalid choice. Try again.")

    await db.disconnect()

# run
if __name__ == '__main__':
    asyncio.run(main())

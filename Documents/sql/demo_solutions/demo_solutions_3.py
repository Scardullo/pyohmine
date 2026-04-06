import asyncio
import asyncpg
import os
from datetime import date
from dotenv import load_dotenv
from rich import print
from rich.table import Table
from asyncpg.exceptions import UniqueViolationError

load_dotenv()

DB_CONFIG = dict(
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    database=os.getenv("DB_NAME"),
)


class BusinessDB:
    def __init__(self):
        self.pool = None

    async def connect(self):
        if self.pool:
            return
        print("[cyan]Connecting to database...[/cyan]")
        self.pool = await asyncpg.create_pool(**DB_CONFIG)

    async def close(self):
        if self.pool:
            await self.pool.close()

    async def fetch(self, q, *args):
        async with self.pool.acquire() as con:
            return await con.fetch(q, *args)

    async def fetchrow(self, q, *args):
        async with self.pool.acquire() as con:
            return await con.fetchrow(q, *args)

    async def execute(self, q, *args):
        async with self.pool.acquire() as con:
            return await con.execute(q, *args)

    # sequence fix

    async def fix_sequence(self, table, id_col):
        async with self.pool.acquire() as con:
            await con.execute(f"""
                SELECT setval(
                    pg_get_serial_sequence('{table}', '{id_col}'),
                    COALESCE((SELECT MAX({id_col}) FROM {table}), 1)
                );
            """)

    async def safe_insert(self, table, id_col, sql, *args):
        try:
            return await self.execute(sql, *args)
        except UniqueViolationError as e:
            await self.fix_sequence(table, id_col)
            return await self.execute(sql, *args)

    # invoices

    async def add_invoice_item(self, invoice_id, desc, qty, price):
        line_total = qty * price

        await self.execute("""
            INSERT INTO invoice_items(invoice_id,line_number,item_description,quantity,unit_price,line_total)
            VALUES(
                $1,
                (SELECT COALESCE(MAX(line_number),0)+1 FROM invoice_items WHERE invoice_id=$1),
                $2,$3,$4,$5
            )
        """, invoice_id, desc, qty, price, line_total)

        await self.recalc_invoice(invoice_id)

    async def recalc_invoice(self, invoice_id):
        await self.execute("""
            UPDATE invoices
            SET subtotal = s.sub,
                total_amount = s.sub,
                balance_due = s.sub - amount_paid
            FROM (
                SELECT COALESCE(SUM(line_total),0) sub
                FROM invoice_items
                WHERE invoice_id=$1
            ) s
            WHERE invoice_id=$1
        """, invoice_id)

    async def record_invoice_payment(self, invoice_id, amount, method, emp_id):
        await self.execute("""
            UPDATE invoices
            SET amount_paid = amount_paid + $2,
                balance_due = total_amount - (amount_paid + $2),
                status = CASE
                    WHEN total_amount <= amount_paid + $2 THEN 'Paid'
                    ELSE 'Partially Paid'
                END,
                payment_date = CURRENT_DATE
            WHERE invoice_id=$1
        """, invoice_id, amount)

        await self.execute("""
            INSERT INTO payment_transactions
            (transaction_type,reference_id,reference_type,transaction_date,amount,payment_method,processed_by)
            VALUES('Invoice Payment',$1,'Invoice',CURRENT_DATE,$2,$3,$4)
        """, invoice_id, amount, method, emp_id)

    # purchase orders

    async def add_po_item(self, po_id, desc, qty, price):
        total = qty * price

        await self.execute("""
            INSERT INTO purchase_order_items
            (po_id,line_number,item_description,quantity,unit_price,line_total)
            VALUES(
                $1,
                (SELECT COALESCE(MAX(line_number),0)+1 FROM purchase_order_items WHERE po_id=$1),
                $2,$3,$4,$5
            )
        """, po_id, desc, qty, price, total)

        await self.recalc_po(po_id)

    async def recalc_po(self, po_id):
        await self.execute("""
            UPDATE purchase_orders
            SET subtotal = s.sub,
                total_amount = s.sub
            FROM (
                SELECT COALESCE(SUM(line_total),0) sub
                FROM purchase_order_items
                WHERE po_id=$1
            ) s
            WHERE po_id=$1
        """, po_id)

    async def receive_po_item(self, po_item_id, qty):
        await self.execute("""
            UPDATE purchase_order_items
            SET received_quantity = received_quantity + $2
            WHERE po_item_id=$1
        """, po_item_id, qty)

    # assets

    async def assign_asset(self, asset_id, emp_id):
        await self.execute("""
            UPDATE it_assets
            SET assigned_to=$2, status='In Use'
            WHERE asset_id=$1
        """, asset_id, emp_id)

    async def update_asset_status(self, asset_id, status):
        await self.execute("""
            UPDATE it_assets
            SET status=$2
            WHERE asset_id=$1
        """, asset_id, status)

    # sales

    async def create_opportunity(self, name, cust_id, rep_id, value):
        await self.safe_insert(
            "sales_opportunities", "opportunity_id",
            """
            INSERT INTO sales_opportunities
            (opportunity_name,customer_id,sales_rep_id,estimated_value,probability)
            VALUES($1,$2,$3,$4,0.1)
            """,
            name, cust_id, rep_id, value
        )

    async def list_opportunities(self):
        return await self.fetch("""
            SELECT o.opportunity_id, o.opportunity_name, c.company_name, o.stage, o.estimated_value
            FROM sales_opportunities o
            JOIN customers c ON c.customer_id=o.customer_id
        """)

# ui helpers

def show_table(title, rows):
    if not rows:
        print("[yellow]No records found[/yellow]")
        return
    table = Table(title=title)
    for col in rows[0].keys():
        table.add_column(col)
    for r in rows:
        table.add_row(*[str(v) for v in r.values()])
    print(table)

def get_int(msg):
    return int(input(msg))

def get_float(msg):
    return float(input(msg))

# menu

async def main():
    db = BusinessDB()
    await db.connect()

    while True:
        print("\n[bold cyan]=== Business DB Manager v2 ===[/bold cyan]")
        print("1. Add Invoice Item")
        print("2. Record Invoice Payment")
        print("3. Add PO Item")
        print("4. Receive PO Item")
        print("5. Assign Asset")
        print("6. Update Asset Status")
        print("7. Add Sales Opportunity")
        print("8. List Sales Opportunities")
        print("0. Exit")

        c = input("Choice: ").strip()

        try:
            if c == "1":
                inv = get_int("Invoice ID: ")
                desc = input("Desc: ")
                qty = get_float("Qty: ")
                price = get_float("Unit price: ")
                await db.add_invoice_item(inv, desc, qty, price)

            elif c == "2":
                inv = get_int("Invoice ID: ")
                amt = get_float("Amount: ")
                method = input("Method: ")
                emp = get_int("Processed by emp id: ")
                await db.record_invoice_payment(inv, amt, method, emp)

            elif c == "3":
                po = get_int("PO ID: ")
                desc = input("Desc: ")
                qty = get_float("Qty: ")
                price = get_float("Unit price: ")
                await db.add_po_item(po, desc, qty, price)

            elif c == "4":
                item = get_int("PO Item ID: ")
                qty = get_float("Qty received: ")
                await db.receive_po_item(item, qty)

            elif c == "5":
                asset = get_int("Asset ID: ")
                emp = get_int("Assign to employee ID: ")
                await db.assign_asset(asset, emp)

            elif c == "6":
                asset = get_int("Asset ID: ")
                status = input("New status: ")
                await db.update_asset_status(asset, status)

            elif c == "7":
                name = input("Opportunity name: ")
                cust = get_int("Customer ID: ")
                rep = get_int("Sales rep ID: ")
                val = get_float("Est value: ")
                await db.create_opportunity(name, cust, rep, val)

            elif c == "8":
                show_table("Sales Opportunities", await db.list_opportunities())

            elif c == "0":
                break

        except Exception as e:
            print(f"[red]Error:[/red] {e}")

    await db.close()

if __name__ == "__main__":
    asyncio.run(main())

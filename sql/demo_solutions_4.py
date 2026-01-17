import asyncio
import asyncpg
import os
from dotenv import load_dotenv
from rich import print
from rich.table import Table
from datetime import date

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
        if not self.pool:
            print("[cyan]Connecting to database...[/cyan]")
            self.pool = await asyncpg.create_pool(**DB_CONFIG)

    async def close(self):
        if self.pool:
            await self.pool.close()

    async def fetch(self, query, *args):
        async with self.pool.acquire() as con:
            return await con.fetch(query, *args)

    async def fetchrow(self, query, *args):
        async with self.pool.acquire() as con:
            return await con.fetchrow(query, *args)

    async def execute(self, query, *args):
        async with self.pool.acquire() as con:
            return await con.execute(query, *args)


# Top Customers by Revenue
    async def top_customers_by_revenue(self, limit=10):
        return await self.fetch("""
            SELECT c.customer_id, c.company_name, SUM(i.total_amount) AS revenue
            FROM invoices i
            JOIN customers c ON i.customer_id = c.customer_id
            WHERE i.status = 'Paid'
            GROUP BY c.customer_id, c.company_name
            ORDER BY revenue DESC
            LIMIT $1
        """, limit)

# Overdue Invoices
    async def overdue_invoices(self):
        return await self.fetch("""
            SELECT invoice_id, invoice_number, customer_id, balance_due, due_date
            FROM invoices
            WHERE balance_due > 0 AND due_date < CURRENT_DATE
            ORDER BY due_date
        """)

# Project Budget vs Actual Cost
    async def project_budget_report(self):
        return await self.fetch("""
            SELECT project_id, project_name, budget, COALESCE(actual_cost,0) AS actual_cost,
                   budget - COALESCE(actual_cost,0) AS remaining_budget
            FROM projects
        """)

# Marketing Campaign ROI
    async def marketing_roi_report(self):
        return await self.fetch("""
            SELECT campaign_name, budget, actual_cost, leads_generated, opportunities_created, revenue_generated,
                   CASE WHEN actual_cost > 0 THEN revenue_generated / actual_cost ELSE 0 END AS roi
            FROM marketing_campaigns
        """)

# Employee Payment Activity
    async def employee_payment_activity(self):
        return await self.fetch("""
            SELECT e.employee_id, e.first_name || ' ' || e.last_name AS employee,
                   COUNT(pt.transaction_id) AS transactions, SUM(pt.amount) AS total_amount
            FROM employees e
            JOIN payment_transactions pt ON e.employee_id = pt.processed_by
            GROUP BY e.employee_id
        """)

# Assets Approaching Warranty Expiry
    async def warranty_alert_assets(self, days=30):
        return await self.fetch("""
            SELECT asset_id, asset_tag, asset_type, brand, model, warranty_expiry
            FROM it_assets
            WHERE warranty_expiry BETWEEN CURRENT_DATE AND CURRENT_DATE + $1::interval
        """, f"{days} days")

# Purchase Order Fulfillment Rate
    async def purchase_order_fulfillment(self):
        return await self.fetch("""
            SELECT po.po_number, SUM(poi.quantity) AS ordered, SUM(poi.received_quantity) AS received,
                   CASE WHEN SUM(poi.quantity) > 0 THEN SUM(poi.received_quantity)/SUM(poi.quantity)::float ELSE 0 END AS fulfillment
            FROM purchase_orders po
            JOIN purchase_order_items poi ON po.po_id = poi.po_id
            GROUP BY po.po_number
        """)


def show_table(title, rows):
    if not rows:
        print(f"[yellow]No records found for {title}[/yellow]")
        return
    table = Table(title=title)
    for col in rows[0].keys():
        table.add_column(col)
    for r in rows:
        table.add_row(*[str(v) if v is not None else "" for v in r.values()])
    print(table)


async def main():
    db = BusinessDB()
    await db.connect()

    while True:
        print("\n[bold cyan]=== Business Insights Menu ===[/bold cyan]")
        print("1. Top Customers by Revenue")
        print("2. Overdue Invoices")
        print("3. Project Budget Report")
        print("4. Marketing Campaign ROI")
        print("5. Employee Payment Activity")
        print("6. Assets Approaching Warranty Expiry")
        print("7. Purchase Order Fulfillment")
        print("0. Exit")

        choice = input("Choice: ").strip()

        if choice == "1":
            rows = await db.top_customers_by_revenue()
            show_table("Top Customers by Revenue", rows)

        elif choice == "2":
            rows = await db.overdue_invoices()
            show_table("Overdue Invoices", rows)

        elif choice == "3":
            rows = await db.project_budget_report()
            show_table("Project Budget vs Actual", rows)

        elif choice == "4":
            rows = await db.marketing_roi_report()
            show_table("Marketing Campaign ROI", rows)

        elif choice == "5":
            rows = await db.employee_payment_activity()
            show_table("Employee Payment Activity", rows)

        elif choice == "6":
            rows = await db.warranty_alert_assets()
            show_table("Assets Approaching Warranty Expiry", rows)

        elif choice == "7":
            rows = await db.purchase_order_fulfillment()
            show_table("Purchase Order Fulfillment", rows)

        elif choice == "0":
            break

        else:
            print("[red]Invalid choice[/red]")

    await db.close()

# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    asyncio.run(main())

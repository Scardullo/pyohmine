#!/usr/bin/env python3
# To run in terminal run these two command:
# source .venv/bin/activate
#./chat_gpt/demo_solutions_2.py 

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

# db class

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

    # wrappers
    async def fetch(self, q, *args):
        async with self.pool.acquire() as con:
            return await con.fetch(q, *args)

    async def fetchrow(self, q, *args):
        async with self.pool.acquire() as con:
            return await con.fetchrow(q, *args)

    async def execute(self, q, *args):
        async with self.pool.acquire() as con:
            return await con.execute(q, *args)

    # sequence auto fix

    async def fix_sequence(self, table, id_col):
        print(f"[yellow]Resyncing sequence for {table}.{id_col}...[/yellow]")
        async with self.pool.acquire() as con:
            await con.execute(f"""
                SELECT setval(
                    pg_get_serial_sequence('{table}', '{id_col}'),
                    COALESCE((SELECT MAX({id_col}) FROM {table}), 1)
                );
            """)
        print("[green]Sequence fixed[/green]")

    async def safe_insert(self, table, id_col, sql, *args):
        try:
            return await self.execute(sql, *args)

        except UniqueViolationError as e:
            msg = str(e).lower()

            if f"{table}_pkey" in msg or id_col in msg:
                await self.fix_sequence(table, id_col)
                print("[yellow]Retrying insert after sequence fix...[/yellow]")
                return await self.execute(sql, *args)

            raise

    # locations

    async def add_location(self, name, address, city, state, postal, phone=None, hq=False):
        return await self.safe_insert(
            "locations", "location_id",
            """
            INSERT INTO locations(location_name,address,city,state,postal_code,phone,is_headquarters)
            VALUES($1,$2,$3,$4,$5,$6,$7)
            """,
            name, address, city, state, postal, phone, hq
        )

    async def list_locations(self):
        return await self.fetch("SELECT * FROM locations ORDER BY location_id")

    # departments

    async def add_department(self, name, desc, location_id, budget):
        return await self.safe_insert(
            "departments", "department_id",
            """
            INSERT INTO departments(department_name,description,location_id,budget)
            VALUES($1,$2,$3,$4)
            """,
            name, desc, location_id, budget
        )

    async def list_departments(self):
        return await self.fetch("""
            SELECT d.department_id, d.department_name, l.location_name
            FROM departments d
            LEFT JOIN locations l ON l.location_id = d.location_id
            ORDER BY d.department_id
        """)

    # employees 

    async def add_employee(self, first, last, email, hire_date, title, dept_id, loc_id, salary):
        return await self.safe_insert(
            "employees", "employee_id",
            """
            INSERT INTO employees(first_name,last_name,email,hire_date,job_title,department_id,location_id,salary)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)
            """,
            first, last, email, hire_date, title, dept_id, loc_id, salary
        )

    async def list_employees(self):
        return await self.fetch("""
            SELECT e.employee_id, first_name, last_name, job_title, d.department_name
            FROM employees e
            JOIN departments d ON d.department_id = e.department_id
            ORDER BY employee_id
        """)

    # customers 

    async def add_customer(self, company, contact, email, tier):
        return await self.safe_insert(
            "customers", "customer_id",
            """
            INSERT INTO customers(company_name,contact_name,email,customer_tier)
            VALUES($1,$2,$3,$4)
            """,
            company, contact, email, tier
        )

    async def list_customers(self):
        return await self.fetch("SELECT customer_id, company_name, customer_tier FROM customers")

    # products

    async def add_product(self, code, name, ptype, price, cost):
        return await self.safe_insert(
            "products", "product_id",
            """
            INSERT INTO products(product_code,product_name,product_type,unit_price,cost)
            VALUES($1,$2,$3,$4,$5)
            """,
            code, name, ptype, price, cost
        )

    async def list_products(self):
        return await self.fetch("""
            SELECT product_id, product_code, product_name, unit_price FROM products
        """)

    # invoices

    async def create_invoice(self, number, customer_id, due_date, created_by):
        return await self.safe_insert(
            "invoices", "invoice_id",
            """
            INSERT INTO invoices(invoice_number,customer_id,invoice_date,due_date,created_by,status)
            VALUES($1,$2,CURRENT_DATE,$3,$4,'Sent')
            """,
            number, customer_id, due_date, created_by
        )

    async def list_invoices(self):
        return await self.fetch("""
            SELECT i.invoice_id, i.invoice_number, c.company_name, i.total_amount, i.status
            FROM invoices i
            JOIN customers c ON c.customer_id = i.customer_id
        """)

    # assets

    async def add_asset(self, tag, atype, brand, model, price, loc_id):
        return await self.safe_insert(
            "it_assets", "asset_id",
            """
            INSERT INTO it_assets(asset_tag,asset_type,brand,model,purchase_price,location_id)
            VALUES($1,$2,$3,$4,$5,$6)
            """,
            tag, atype, brand, model, price, loc_id
        )

    async def list_assets(self):
        return await self.fetch("""
            SELECT asset_id, asset_tag, asset_type, status FROM it_assets
        """)

    # projects

    async def create_project(self, code, name, cust_id, pm_id):
        return await self.safe_insert(
            "projects", "project_id",
            """
            INSERT INTO projects(project_code,project_name,customer_id,project_manager_id,start_date)
            VALUES($1,$2,$3,$4,CURRENT_DATE)
            """,
            code, name, cust_id, pm_id
        )

    async def list_projects(self):
        return await self.fetch("""
            SELECT project_id, project_name, status FROM projects
        """)

    # purchase orders 

    async def create_purchase_order(self, po_number, vendor_id, requested_by, expected_delivery=None):
        return await self.safe_insert(
            "purchase_orders", "po_id",
            """
            INSERT INTO purchase_orders(po_number,vendor_id,order_date,requested_by,expected_delivery_date,status)
            VALUES($1,$2,CURRENT_DATE,$3,$4,'Draft')
            """,
            po_number, vendor_id, requested_by, expected_delivery
        )

    async def list_purchase_orders(self):
        return await self.fetch("""
            SELECT po_id, po_number, status, order_date, expected_delivery_date
            FROM purchase_orders
            ORDER BY po_id
        """)

    # bills

    async def create_bill(self, bill_number, vendor_id, po_id=None, bill_date=None, due_date=None):
        bill_date = bill_date or date.today()
        due_date = due_date or date.today()
        return await self.safe_insert(
            "bills", "bill_id",
            """
            INSERT INTO bills(bill_number,vendor_id,po_id,bill_date,due_date,status)
            VALUES($1,$2,$3,$4,$5,'Pending')
            """,
            bill_number, vendor_id, po_id, bill_date, due_date
        )

    async def list_bills(self):
        return await self.fetch("""
            SELECT bill_id, bill_number, vendor_id, status, bill_date, due_date
            FROM bills
            ORDER BY bill_id
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


# menu

async def main():
    db = BusinessDB()
    await db.connect()

    while True:
        print("\n[bold cyan]=== Business DB Manager ===[/bold cyan]")
        print("1. List Employees")
        print("2. Add Employee")
        print("3. List Customers")
        print("4. Add Customer")
        print("5. List Products")
        print("6. Add Product")
        print("7. Create Invoice")
        print("8. Add IT Asset")
        print("9. List Projects")
        print("10. List Purchase Orders")
        print("11. Add Purchase Order")
        print("12. List Bills")
        print("13. Add Bill")
        print("14. Add Location")
        print("15. List Locations")
        print("16. Add Department")
        print("17. List Departments")
        print("18. Add Project")
        print("0. Exit")

        c = input("Choice: ").strip()

        try:
            if c == "1":
                show_table("Employees", await db.list_employees())

            elif c == "2":
                f = input("First: ")
                l = input("Last: ")
                e = input("Email: ")
                d = int(input("Dept ID: "))
                loc = int(input("Location ID: "))
                s = float(input("Salary: "))
                await db.add_employee(f, l, e, date.today(), "Staff", d, loc, s)

            elif c == "3":
                show_table("Customers", await db.list_customers())

            elif c == "4":
                company = input("Company: ")
                contact = input("Contact: ")
                email = input("Email: ")
                tier = input("Tier: ")
                await db.add_customer(company, contact, email, tier)

            elif c == "5":
                show_table("Products", await db.list_products())

            elif c == "6":
                code = input("Code: ")
                name = input("Name: ")
                ptype = input("Type: ")
                price = float(input("Price: "))
                cost = float(input("Cost: "))
                await db.add_product(code, name, ptype, price, cost)

            elif c == "7":
                num = input("Invoice #: ")
                cust = int(input("Customer ID: "))
                due = date.fromisoformat(input("Due date YYYY-MM-DD: "))
                emp = int(input("Created by employee ID: "))
                await db.create_invoice(num, cust, due, emp)

            elif c == "8":
                tag = input("Asset tag: ")
                at = input("Type: ")
                brand = input("Brand: ")
                model = input("Model: ")
                price = float(input("Price: "))
                loc = int(input("Location ID: "))
                await db.add_asset(tag, at, brand, model, price, loc)

            elif c == "9":
                show_table("Projects", await db.list_projects())

            elif c == "10":
                show_table("Purchase Orders", await db.list_purchase_orders())

            elif c == "11":
                po_number = input("PO #: ")
                vendor_id = int(input("Vendor ID: "))
                requested_by = int(input("Requested by employee ID: "))
                await db.create_purchase_order(po_number, vendor_id, requested_by)

            elif c == "12":
                show_table("Bills", await db.list_bills())

            elif c == "13":
                bill_number = input("Bill #: ")
                vendor_id = int(input("Vendor ID: "))
                po_id_input = input("PO ID (optional): ").strip()
                po_id = int(po_id_input) if po_id_input else None
                await db.create_bill(bill_number, vendor_id, po_id)

            elif c == "14":
                name = input("name: ")
                address = input("address: ")
                city = input("city: ")
                state = input("state: ")
                postal = input("zip code: ")
                phone = input("phone: ")
                await db.add_location(name, address, city, state, postal, phone)

            elif c == "15":
                show_table("Locations", await db.list_locations())

            elif c == "16":
                name = input("name: ") 
                desc = input("description: ")
                location_id = input("location_id: ")
                budget = input("budget: ")
                await db.add_department(name, desc, location_id, budget)

            elif c == "17":
                show_table("Departments", await db.list_departments())

            elif c == "18":
                code = input("code: ")
                name = input("name: ")
                cust_id = get_int("customer id: ")
                pm_id = get_int("project manager id: ")
                await db.create_project(code, name, cust_id, pm_id)

            elif c == "0":
                break

        except Exception as e:
            print(f"[red]Error:[/red] {e}")

    await db.close()

if __name__ == "__main__":
    asyncio.run(main())

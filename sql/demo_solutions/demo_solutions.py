import asyncio
import asyncpg
import os
from datetime import date
from dotenv import load_dotenv
from rich import print
from rich.table import Table

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

    # generic helpers

    async def fetch(self, q, *args):
        async with self.pool.acquire() as con:
            return await con.fetch(q, *args)

    async def fetchrow(self, q, *args):
        async with self.pool.acquire() as con:
            return await con.fetchrow(q, *args)

    async def execute(self, q, *args):
        async with self.pool.acquire() as con:
            return await con.execute(q, *args)

    # locations

    async def add_location(self, name, address, city, state, postal, phone=None, hq=False):
        return await self.execute("""
            INSERT INTO locations(location_name,address,city,state,postal_code,phone,is_headquarters)
            VALUES($1,$2,$3,$4,$5,$6,$7)
        """, name, address, city, state, postal, phone, hq)

    async def list_locations(self):
        return await self.fetch("SELECT * FROM locations ORDER BY location_id")

    # departments

    async def add_department(self, name, desc, location_id, budget):
        return await self.execute("""
            INSERT INTO departments(department_name,description,location_id,budget)
            VALUES($1,$2,$3,$4)
        """, name, desc, location_id, budget)

    async def list_departments(self):
        return await self.fetch("""
            SELECT d.department_id, d.department_name, l.location_name
            FROM departments d
            LEFT JOIN locations l ON l.location_id = d.location_id
            ORDER BY d.department_id
        """)

    # employees

    async def add_employee(self, first, last, email, hire_date, title, dept_id, loc_id, salary):
        return await self.execute("""
            INSERT INTO employees(first_name,last_name,email,hire_date,job_title,department_id,location_id,salary)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)
        """, first, last, email, hire_date, title, dept_id, loc_id, salary)

    async def list_employees(self):
        return await self.fetch("""
            SELECT e.employee_id, first_name, last_name, job_title, d.department_name
            FROM employees e
            JOIN departments d ON d.department_id = e.department_id
            ORDER BY employee_id
        """)

    # customers

    async def add_customer(self, company, contact, email, tier):
        return await self.execute("""
            INSERT INTO customers(company_name,contact_name,email,customer_tier)
            VALUES($1,$2,$3,$4)
        """, company, contact, email, tier)

    async def list_customers(self):
        return await self.fetch("SELECT customer_id, company_name, customer_tier FROM customers")

    # products

    async def add_product(self, code, name, ptype, price, cost):
        return await self.execute("""
            INSERT INTO products(product_code,product_name,product_type,unit_price,cost)
            VALUES($1,$2,$3,$4,$5)
        """, code, name, ptype, price, cost)

    async def list_products(self):
        return await self.fetch("""
            SELECT product_id, product_code, product_name, unit_price FROM products
        """)

    # invoices

    async def create_invoice(self, number, customer_id, due_date, created_by):
        return await self.execute("""
            INSERT INTO invoices(invoice_number,customer_id,invoice_date,due_date,created_by,status)
            VALUES($1,$2,CURRENT_DATE,$3,$4,'Sent')
        """, number, customer_id, due_date, created_by)

    async def add_invoice_item(self, invoice_id, line, desc, qty, price):
        total = qty * price
        return await self.execute("""
            INSERT INTO invoice_items(invoice_id,line_number,item_description,quantity,unit_price,line_total)
            VALUES($1,$2,$3,$4,$5,$6)
        """, invoice_id, line, desc, qty, price, total)

    async def list_invoices(self):
        return await self.fetch("""
            SELECT i.invoice_id, i.invoice_number, c.company_name, i.total_amount, i.status
            FROM invoices i
            JOIN customers c ON c.customer_id = i.customer_id
        """)

    # payments

    async def apply_invoice_payment(self, invoice_id, amount, method, employee_id):
        async with self.pool.acquire() as con:
            async with con.transaction():
                await con.execute("""
                    INSERT INTO payment_transactions(transaction_type,reference_id,transaction_date,amount,payment_method,processed_by)
                    VALUES('Invoice Payment',$1,CURRENT_DATE,$2,$3,$4)
                """, invoice_id, amount, method, employee_id)

                await con.execute("""
                    UPDATE invoices
                    SET amount_paid = COALESCE(amount_paid,0) + $1
                    WHERE invoice_id = $2
                """, amount, invoice_id)

    # it assets

    async def add_asset(self, tag, atype, brand, model, price, loc_id):
        return await self.execute("""
            INSERT INTO it_assets(asset_tag,asset_type,brand,model,purchase_price,location_id)
            VALUES($1,$2,$3,$4,$5,$6)
        """, tag, atype, brand, model, price, loc_id)

    async def list_assets(self):
        return await self.fetch("""
            SELECT asset_id, asset_tag, asset_type, status FROM it_assets
        """)

    # projects

    async def create_project(self, code, name, cust_id, pm_id):
        return await self.execute("""
            INSERT INTO projects(project_code,project_name,customer_id,project_manager_id,start_date)
            VALUES($1,$2,$3,$4,CURRENT_DATE)
        """, code, name, cust_id, pm_id)

    async def list_projects(self):
        return await self.fetch("""
            SELECT project_id, project_name, status FROM projects
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
        print("0. Exit")

        c = input("Choice: ").strip()

        try:
            if c == "1":
                rows = await db.list_employees()
                show_table("Employees", rows)

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

            elif c == "0":
                break

        except Exception as e:
            print(f"[red]Error:[/red] {e}")

    await db.close()

if __name__ == "__main__":
    asyncio.run(main())

SET client_encoding = 'UTF8';

DROP TABLE IF EXISTS bill_items CASCADE;
DROP TABLE IF EXISTS bills CASCADE;
DROP TABLE IF EXISTS campaign_leads CASCADE;
DROP TABLE IF EXISTS payment_transactions CASCADE;
DROP TABLE IF EXISTS invoice_items CASCADE;
DROP TABLE IF EXISTS invoices CASCADE;
DROP TABLE IF EXISTS purchase_order_items CASCADE;
DROP TABLE IF EXISTS purchase_orders CASCADE;
DROP TABLE IF EXISTS sales_opportunities CASCADE;
DROP TABLE IF EXISTS project_team CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS it_assets CASCADE;
DROP TABLE IF EXISTS marketing_campaigns CASCADE;
DROP TABLE IF EXISTS employees CASCADE;
DROP TABLE IF EXISTS departments CASCADE;
DROP TABLE IF EXISTS products CASCADE;
DROP TABLE IF EXISTS customers CASCADE;
DROP TABLE IF EXISTS vendors CASCADE;
DROP TABLE IF EXISTS locations CASCADE;

CREATE TABLE locations (
    location_id SERIAL PRIMARY KEY,
    location_name TEXT NOT NULL,
    address TEXT NOT NULL,
    city TEXT NOT NULL,
    state TEXT NOT NULL,
    postal_code TEXT NOT NULL,
    phone TEXT,
    is_headquarters BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vendors (
    vendor_id SERIAL PRIMARY KEY,
    vendor_name TEXT NOT NULL,
    contact_name TEXT,
    email TEXT,
    phone TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    postal_code TEXT,
    vendor_type TEXT,
    payment_terms TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE customers (
    customer_id SERIAL PRIMARY KEY,
    company_name TEXT NOT NULL,
    contact_name TEXT,
    email TEXT,
    phone TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    postal_code TEXT,
    industry TEXT,
    customer_tier TEXT CHECK(customer_tier IN ('Enterprise', 'Mid-Market', 'Small Business', 'Startup')),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    product_id SERIAL PRIMARY KEY,
    product_code TEXT NOT NULL UNIQUE,
    product_name TEXT NOT NULL,
    description TEXT,
    product_type TEXT CHECK(product_type IN ('Software License', 'Subscription', 'Professional Services', 'Support', 'Hardware')),
    unit_price NUMERIC(12,2),
    cost NUMERIC(12,2),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE departments (
    department_id SERIAL PRIMARY KEY,
    department_name TEXT NOT NULL UNIQUE,
    description TEXT,
    location_id INTEGER,
    manager_id INTEGER,
    budget NUMERIC(15,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (location_id) REFERENCES locations(location_id)
);

CREATE TABLE employees (
    employee_id SERIAL PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    hire_date DATE NOT NULL,
    job_title TEXT NOT NULL,
    department_id INTEGER NOT NULL,
    location_id INTEGER NOT NULL,
    manager_id INTEGER,
    salary NUMERIC(12,2),
    employment_status TEXT CHECK(employment_status IN ('Active', 'On Leave', 'Terminated')) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (department_id) REFERENCES departments(department_id),
    FOREIGN KEY (location_id) REFERENCES locations(location_id),
    FOREIGN KEY (manager_id) REFERENCES employees(employee_id)
);

CREATE TABLE marketing_campaigns (
    campaign_id SERIAL PRIMARY KEY,
    campaign_name TEXT NOT NULL,
    campaign_type TEXT CHECK(campaign_type IN ('Email', 'Social Media', 'Webinar', 'Trade Show', 'Content Marketing', 'PPC', 'SEO')),
    start_date DATE NOT NULL,
    end_date DATE,
    budget NUMERIC(15,2),
    actual_cost NUMERIC(15,2),
    target_audience TEXT,
    status TEXT CHECK(status IN ('Planning', 'Active', 'Completed', 'Cancelled')) DEFAULT 'Planning',
    leads_generated INTEGER DEFAULT 0,
    opportunities_created INTEGER DEFAULT 0,
    revenue_generated NUMERIC(15,2) DEFAULT 0,
    owner_id INTEGER NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES employees(employee_id)
);

CREATE TABLE it_assets (
    asset_id SERIAL PRIMARY KEY,
    asset_tag TEXT NOT NULL UNIQUE,
    asset_type TEXT CHECK(asset_type IN ('Laptop', 'Desktop', 'Server', 'Network Equipment', 'Mobile Device', 'Monitor', 'Printer', 'Software License')),
    brand TEXT,
    model TEXT,
    serial_number TEXT,
    purchase_date DATE,
    purchase_price NUMERIC(12,2),
    warranty_expiry DATE,
    assigned_to INTEGER,
    location_id INTEGER,
    status TEXT CHECK(status IN ('In Use', 'Available', 'In Repair', 'Retired', 'Lost')) DEFAULT 'Available',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assigned_to) REFERENCES employees(employee_id),
    FOREIGN KEY (location_id) REFERENCES locations(location_id)
);

CREATE TABLE projects (
    project_id SERIAL PRIMARY KEY,
    project_code TEXT NOT NULL UNIQUE,
    project_name TEXT NOT NULL,
    description TEXT,
    customer_id INTEGER,
    project_manager_id INTEGER NOT NULL,
    start_date DATE NOT NULL,
    planned_end_date DATE,
    actual_end_date DATE,
    status TEXT CHECK(status IN ('Planning', 'In Progress', 'On Hold', 'Completed', 'Cancelled')) DEFAULT 'Planning',
    budget NUMERIC(15,2),
    actual_cost NUMERIC(15,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    FOREIGN KEY (project_manager_id) REFERENCES employees(employee_id)
);

CREATE TABLE project_team (
    project_team_id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL,
    employee_id INTEGER NOT NULL,
    role TEXT,
    allocation_percentage NUMERIC(5,2),
    start_date DATE,
    end_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(project_id),
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id),
    UNIQUE(project_id, employee_id)
);

CREATE TABLE sales_opportunities (
    opportunity_id SERIAL PRIMARY KEY,
    opportunity_name TEXT NOT NULL,
    customer_id INTEGER NOT NULL,
    sales_rep_id INTEGER NOT NULL,
    stage TEXT CHECK(stage IN ('Prospecting', 'Qualification', 'Proposal', 'Negotiation', 'Closed Won', 'Closed Lost')) DEFAULT 'Prospecting',
    probability NUMERIC(5,2),
    estimated_value NUMERIC(15,2),
    expected_close_date DATE,
    actual_close_date DATE,
    next_step TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    FOREIGN KEY (sales_rep_id) REFERENCES employees(employee_id)
);

CREATE TABLE purchase_orders (
    po_id SERIAL PRIMARY KEY,
    po_number TEXT NOT NULL UNIQUE,
    vendor_id INTEGER NOT NULL,
    order_date DATE NOT NULL,
    expected_delivery_date DATE,
    actual_delivery_date DATE,
    status TEXT CHECK(status IN ('Draft', 'Pending Approval', 'Approved', 'Ordered', 'Partially Received', 'Received', 'Cancelled')) DEFAULT 'Draft',
    requested_by INTEGER NOT NULL,
    approved_by INTEGER,
    subtotal NUMERIC(15,2),
    tax NUMERIC(15,2),
    shipping NUMERIC(15,2),
    total_amount NUMERIC(15,2),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id),
    FOREIGN KEY (requested_by) REFERENCES employees(employee_id),
    FOREIGN KEY (approved_by) REFERENCES employees(employee_id)
);

CREATE TABLE purchase_order_items (
    po_item_id SERIAL PRIMARY KEY,
    po_id INTEGER NOT NULL,
    line_number INTEGER NOT NULL,
    item_description TEXT NOT NULL,
    quantity NUMERIC(10,2) NOT NULL,
    unit_price NUMERIC(12,2) NOT NULL,
    line_total NUMERIC(15,2) NOT NULL,
    received_quantity NUMERIC(10,2) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (po_id) REFERENCES purchase_orders(po_id)
);

CREATE TABLE invoices (
    invoice_id SERIAL PRIMARY KEY,
    invoice_number TEXT NOT NULL UNIQUE,
    customer_id INTEGER NOT NULL,
    invoice_date DATE NOT NULL,
    due_date DATE NOT NULL,
    payment_date DATE,
    status TEXT CHECK(status IN ('Draft', 'Sent', 'Partially Paid', 'Paid', 'Overdue', 'Cancelled')) DEFAULT 'Draft',
    subtotal NUMERIC(15,2),
    tax NUMERIC(15,2),
    total_amount NUMERIC(15,2),
    amount_paid NUMERIC(15,2) DEFAULT 0,
    balance_due NUMERIC(15,2),
    payment_method TEXT,
    notes TEXT,
    created_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    FOREIGN KEY (created_by) REFERENCES employees(employee_id)
);

CREATE TABLE invoice_items (
    invoice_item_id SERIAL PRIMARY KEY,
    invoice_id INTEGER NOT NULL,
    line_number INTEGER NOT NULL,
    product_id INTEGER,
    item_description TEXT NOT NULL,
    quantity NUMERIC(10,2) NOT NULL,
    unit_price NUMERIC(12,2) NOT NULL,
    line_total NUMERIC(15,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (invoice_id) REFERENCES invoices(invoice_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id)
);

CREATE TABLE bills (
    bill_id SERIAL PRIMARY KEY,
    bill_number TEXT NOT NULL UNIQUE,
    vendor_id INTEGER NOT NULL,
    po_id INTEGER,
    bill_date DATE NOT NULL,
    due_date DATE NOT NULL,
    payment_date DATE,
    status TEXT CHECK(status IN ('Pending', 'Approved', 'Partially Paid', 'Paid', 'Overdue', 'Cancelled')) DEFAULT 'Pending',
    subtotal NUMERIC(15,2),
    tax NUMERIC(15,2),
    total_amount NUMERIC(15,2),
    amount_paid NUMERIC(15,2) DEFAULT 0,
    balance_due NUMERIC(15,2),
    payment_method TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id),
    FOREIGN KEY (po_id) REFERENCES purchase_orders(po_id)
);

CREATE TABLE bill_items (
    bill_item_id SERIAL PRIMARY KEY,
    bill_id INTEGER NOT NULL,
    line_number INTEGER NOT NULL,
    item_description TEXT NOT NULL,
    quantity NUMERIC(10,2) NOT NULL,
    unit_price NUMERIC(12,2) NOT NULL,
    line_total NUMERIC(15,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bill_id) REFERENCES bills(bill_id)
);

CREATE TABLE payment_transactions (
    transaction_id SERIAL PRIMARY KEY,
    transaction_type TEXT CHECK(transaction_type IN ('Invoice Payment', 'Bill Payment', 'Refund', 'Adjustment')),
    reference_id INTEGER,
    reference_type TEXT,
    transaction_date DATE NOT NULL,
    amount NUMERIC(15,2) NOT NULL,
    payment_method TEXT CHECK(payment_method IN ('Check', 'Wire Transfer', 'ACH', 'Credit Card', 'PayPal', 'Other')),
    transaction_number TEXT UNIQUE,
    processed_by INTEGER,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (processed_by) REFERENCES employees(employee_id)
);

CREATE TABLE campaign_leads (
    lead_id SERIAL PRIMARY KEY,
    campaign_id INTEGER NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    company_name TEXT,
    job_title TEXT,
    lead_source TEXT,
    lead_status TEXT CHECK(lead_status IN ('New', 'Contacted', 'Qualified', 'Converted', 'Disqualified')) DEFAULT 'New',
    assigned_to INTEGER,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_id) REFERENCES marketing_campaigns(campaign_id),
    FOREIGN KEY (assigned_to) REFERENCES employees(employee_id)
);

CREATE INDEX idx_employees_dept ON employees(department_id);
CREATE INDEX idx_employees_location ON employees(location_id);
CREATE INDEX idx_employees_manager ON employees(manager_id);
CREATE INDEX idx_purchase_orders_vendor ON purchase_orders(vendor_id);
CREATE INDEX idx_purchase_orders_status ON purchase_orders(status);
CREATE INDEX idx_invoices_customer ON invoices(customer_id);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_bills_vendor ON bills(vendor_id);
CREATE INDEX idx_bills_status ON bills(status);
CREATE INDEX idx_sales_opportunities_customer ON sales_opportunities(customer_id);
CREATE INDEX idx_sales_opportunities_sales_rep ON sales_opportunities(sales_rep_id);
CREATE INDEX idx_projects_customer ON projects(customer_id);
CREATE INDEX idx_projects_pm ON projects(project_manager_id);

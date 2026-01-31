SELECT e.employee_id, e.first_name, e.last_name,
       d.department_name,
       m.first_name || ' ' || m.last_name AS manager_name
FROM employees e
JOIN departments d ON e.department_id = d.department_id
LEFT JOIN employees m ON e.manager_id = m.employee_id;


SELECT d.department_name, l.location_name, COUNT(*) AS headcount
FROM employees e
JOIN departments d ON e.department_id = d.department_id
JOIN locations l ON e.location_id = l.location_id
WHERE e.employment_status = 'Active'
GROUP BY d.department_name, l.location_name
ORDER BY headcount DESC;


SELECT d.department_name,
       d.budget,
       SUM(e.salary) AS total_salary,
       d.budget - SUM(e.salary) AS budget_remaining
FROM departments d
JOIN employees e ON e.department_id = d.department_id
GROUP BY d.department_id;


SELECT *
FROM employees
WHERE hire_date >= CURRENT_DATE - INTERVAL '90 days';


SELECT c.company_name, SUM(i.total_amount) AS revenue
FROM customers c
JOIN invoices i ON i.customer_id = c.customer_id
WHERE i.status = 'Paid'
GROUP BY c.customer_id
ORDER BY revenue DESC;


SELECT stage, COUNT(*) AS deals, SUM(estimated_value) AS pipeline_value
FROM sales_opportunities
WHERE stage NOT IN ('Closed Won', 'Closed Lost')
GROUP BY stage;


SELECT e.first_name, e.last_name,
       COUNT(*) FILTER (WHERE o.stage = 'Closed Won')::float /
       NULLIF(COUNT(*),0) AS win_rate
FROM sales_opportunities o
JOIN employees e ON o.sales_rep_id = e.employee_id
GROUP BY e.employee_id;


SELECT c.*
FROM customers c
LEFT JOIN invoices i ON i.customer_id = c.customer_id
WHERE i.invoice_id IS NULL;


SELECT invoice_number, customer_id,
       CURRENT_DATE - due_date AS days_overdue,
       balance_due
FROM invoices
WHERE status = 'Overdue';


UPDATE invoices
SET amount_paid = amount_paid + 500,
    balance_due = balance_due - 500,
    status = CASE
        WHEN balance_due - 500 <= 0 THEN 'Paid'
        ELSE 'Partially Paid'
    END,
    payment_date = CURRENT_DATE
WHERE invoice_id = 42;


INSERT INTO payment_transactions
(transaction_type, reference_id, reference_type, transaction_date, amount, payment_method, processed_by)
VALUES ('Invoice Payment', 42, 'Invoice', CURRENT_DATE, 500, 'ACH', 7);


SELECT DATE_TRUNC('month', invoice_date) AS month, -- chops the date down to the first day of that month
       SUM(total_amount) AS revenue
FROM invoices
WHERE status IN ('Paid','Partially Paid')
GROUP BY month
ORDER BY month;


SELECT po.po_number,
       ROUND( SUM(poi.received_quantity) / NULLIF(SUM(poi.quantity),0), 2) AS fulfillment_rate
FROM purchase_orders po
JOIN purchase_order_items poi ON po.po_id = poi.po_id
GROUP BY po.po_number;


SELECT v.vendor_name, COUNT(*) AS late_orders
FROM purchase_orders po
JOIN vendors v ON po.vendor_id = v.vendor_id
WHERE po.actual_delivery_date > po.expected_delivery_date
GROUP BY v.vendor_name;


SELECT *
FROM bills
WHERE po_id IS NULL;


SELECT v.vendor_name, SUM(b.total_amount) AS spend
FROM bills b
JOIN vendors v ON b.vendor_id = v.vendor_id
WHERE b.status IN ('Paid','Partially Paid')
GROUP BY v.vendor_name
ORDER BY spend DESC;


SELECT e.first_name, e.last_name, COUNT(a.asset_id) AS asset_count
FROM employees e
LEFT JOIN it_assets a ON a.assigned_to = e.employee_id
GROUP BY e.employee_id;


SELECT e.first_name || ' ' || e.last_name AS employee, COUNT(a.asset_id) AS asset_count
FROM employees e
LEFT JOIN it_assets a ON a.assigned_to = e.employee_id
GROUP BY e.employee_id ORDER BY employee; -- or ORDER BY e.last_name


SELECT *
FROM it_assets
WHERE warranty_expiry <= CURRENT_DATE + INTERVAL '60 days';


UPDATE it_assets
SET assigned_to = 12,
    status = 'In Use'
WHERE asset_tag = 'LT-2049';


SELECT l.location_name, a.asset_type, COUNT(*)
FROM it_assets a
JOIN locations l ON a.location_id = l.location_id
GROUP BY l.location_name, a.asset_type;


SELECT campaign_name,
       revenue_generated - actual_cost AS profit,
       ROUND(
           (revenue_generated - actual_cost) / NULLIF(actual_cost, 0),
           2
       ) AS roi
FROM marketing_campaigns;


SELECT c.campaign_name,
       ROUND(
           (COUNT(*) FILTER (WHERE l.lead_status='Converted')::float
            / COUNT(*))::numeric,
           2
       ) AS conversion_rate
FROM marketing_campaigns c
JOIN campaign_leads l ON l.campaign_id = c.campaign_id
GROUP BY c.campaign_id;


UPDATE campaign_leads
SET assigned_to = 5
WHERE lead_status = 'New'
  AND created_at < CURRENT_DATE - INTERVAL '7 days';


SELECT project_name,
       actual_cost - budget AS overrun
FROM projects
WHERE actual_cost > budget;


SELECT e.first_name, e.last_name,
       SUM(pt.allocation_percentage) AS total_alloc
FROM project_team pt
JOIN employees e ON pt.employee_id = e.employee_id
GROUP BY e.employee_id;


SELECT p.*
FROM projects p
LEFT JOIN project_team pt ON p.project_id = pt.project_id
WHERE pt.project_id IS NULL;


SELECT *
FROM (
    SELECT c.state, c.company_name,
           SUM(i.total_amount) AS revenue,
           RANK() OVER (PARTITION BY c.state ORDER BY SUM(i.total_amount) DESC) r
    FROM customers c
    JOIN invoices i ON i.customer_id = c.customer_id
    GROUP BY c.state, c.company_name
) t
WHERE r <= 3;


SELECT
    COUNT(*) FILTER (WHERE employment_status='Terminated')::float /
    COUNT(*) AS turnover_rate
FROM employees;


WITH yearly AS (
  SELECT customer_id,
         DATE_PART('year', invoice_date) AS yr,
         SUM(total_amount) AS revenue
  FROM invoices
  GROUP BY customer_id, yr
)
SELECT y1.customer_id
FROM yearly y1
JOIN yearly y2
  ON y1.customer_id = y2.customer_id
 AND y1.yr = y2.yr + 1
WHERE y1.revenue < y2.revenue;




BEGIN;

INSERT INTO purchase_orders (po_number, vendor_id, order_date, status, requested_by)
VALUES ('PO-90012', 3, CURRENT_DATE, 'Ordered', 7)
RETURNING po_id;

-- assume returned po_id = 55

INSERT INTO purchase_order_items (po_id, line_number, item_description, quantity, unit_price, line_total)
VALUES
(55, 1, 'Dell Monitors', 5, 220, 1100),
(55, 2, 'Docking Stations', 5, 180, 900);

COMMIT;



-- OPTION 1 (psql / SQL block) <- procedural language 
BEGIN;

-- store the new po_id in a variable
DO $$
DECLARE
    new_po_id INT;
BEGIN
    INSERT INTO purchase_orders (po_number, vendor_id, order_date, status, requested_by)
    VALUES ('PO-90012', 3, CURRENT_DATE, 'Ordered', 7)
    RETURNING po_id INTO new_po_id;

    -- now use the variable automatically
    INSERT INTO purchase_order_items (po_id, line_number, item_description, quantity, unit_price, line_total)
    VALUES
        (new_po_id, 1, 'Dell Monitors', 5, 220, 1100),
        (new_po_id, 2, 'Docking Stations', 5, 180, 900);
END -- only closes the procedural BEGIN block
$$; -- DO $$ … $$  <- The $$; that follows ends the DO statement itself.

COMMIT;



-- OPTION 2 (WITH ... AS)
WITH new_po AS (
    INSERT INTO purchase_orders (po_number, vendor_id, order_date, status, requested_by)
    VALUES ('PO-90013', 3, CURRENT_DATE, 'Ordered', 7)
    RETURNING po_id
)
INSERT INTO purchase_order_items (po_id, line_number, item_description, quantity, unit_price, line_total)
SELECT
    po_id,
    v.line_number,
    v.item_description,
    v.quantity,
    v.unit_price,
    v.line_total
FROM new_po
CROSS JOIN ( -- -> 'CROSS JOIN' combines new po_id with every row inside the VALUES list
    VALUES
        (1, 'Dell Monitors', 5, 220, 1100),
        (2, 'Docking Stations', 5, 180, 900)
) AS v(line_number, item_description, quantity, unit_price, line_total);



SELECT *
FROM employees
WHERE manager_id IS NULL
  AND job_title NOT ILIKE '%Chief%';


SELECT i.invoice_id, i.total_amount, SUM(ii.line_total) AS calc_total
FROM invoices i
JOIN invoice_items ii ON ii.invoice_id = i.invoice_id
GROUP BY i.invoice_id
HAVING i.total_amount <> SUM(ii.line_total);


-- Update invoices to match sum of line items + tax
UPDATE invoices i
SET total_amount = COALESCE(ii_sum.calc_total,0) + COALESCE(i.tax,0)
FROM (
    SELECT invoice_id, SUM(line_total) AS calc_total
    FROM invoice_items
    GROUP BY invoice_id
) ii_sum
WHERE i.invoice_id = ii_sum.invoice_id
  AND i.total_amount <> COALESCE(ii_sum.calc_total,0) + COALESCE(i.tax,0);


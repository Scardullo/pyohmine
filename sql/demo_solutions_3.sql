--Monthly Profit (Revenue − Vendor Spend)

WITH revenue AS (
    SELECT DATE_TRUNC('month', invoice_date) m, SUM(total_amount) rev
    FROM invoices
    WHERE status IN ('Paid','Partially Paid')
    GROUP BY m
),
spend AS (
    SELECT DATE_TRUNC('month', bill_date) m, SUM(total_amount) cost
    FROM bills
    WHERE status IN ('Paid','Partially Paid')
    GROUP BY m
)
SELECT
    COALESCE(r.m, s.m) AS month,
    COALESCE(rev,0) AS revenue,
    COALESCE(cost,0) AS spend,
    COALESCE(rev,0) - COALESCE(cost,0) AS profit
FROM revenue r
FULL JOIN spend s ON r.m = s.m
ORDER BY month;


--Customers With Growing Outstanding Balance

SELECT c.company_name,
       SUM(i.balance_due) AS total_due
FROM customers c
JOIN invoices i ON i.customer_id = c.customer_id
WHERE i.status IN ('Overdue','Partially Paid')
GROUP BY c.customer_id
HAVING SUM(i.balance_due) > 10000
ORDER BY total_due DESC;


--Weighted Sales Pipeline (Probability × Deal Value)

SELECT
    e.first_name, e.last_name,
    SUM(o.estimated_value * (o.probability / 100)) AS weighted_pipeline
FROM sales_opportunities o
JOIN employees e ON e.employee_id = o.sales_rep_id
WHERE o.stage NOT IN ('Closed Won','Closed Lost')
GROUP BY e.employee_id
ORDER BY weighted_pipeline DESC;


--Avg Days to Close Deals (by Sales Rep)

SELECT
    e.first_name, e.last_name,
    AVG(o.actual_close_date - o.created_at::date) AS avg_days_to_close
FROM sales_opportunities o
JOIN employees e ON e.employee_id = o.sales_rep_id
WHERE o.stage = 'Closed Won'
GROUP BY e.employee_id;


--Department Salary vs Budget (With % Used)

SELECT
    d.department_name,
    d.budget,
    SUM(e.salary) AS salary_total,
    ROUND( (SUM(e.salary) / d.budget) * 100, 2) AS pct_budget_used
FROM departments d
JOIN employees e ON e.department_id = d.department_id
GROUP BY d.department_id;


--Managers With Too Many Direct Reports

SELECT
    m.first_name, m.last_name,
    COUNT(e.employee_id) AS reports
FROM employees m
JOIN employees e ON e.manager_id = m.employee_id
GROUP BY m.employee_id
HAVING COUNT(*) >= 8;


--Projects at Risk (Over Budget OR Late)

SELECT
    project_name,
    budget, actual_cost,
    planned_end_date, CURRENT_DATE AS today
FROM projects
WHERE
    (actual_cost > budget)
    OR
    (planned_end_date < CURRENT_DATE AND status <> 'Completed');


--Employees Overallocated Across Projects

SELECT
    e.first_name, e.last_name,
    SUM(pt.allocation_percentage) AS total_alloc
FROM project_team pt
JOIN employees e ON e.employee_id = pt.employee_id
GROUP BY e.employee_id
HAVING SUM(pt.allocation_percentage) > 100;


--Vendors With Highest Late Delivery Rate

SELECT
    v.vendor_name,
    COUNT(*) FILTER (WHERE po.actual_delivery_date > po.expected_delivery_date)::float
    / COUNT(*) AS late_rate
FROM purchase_orders po
JOIN vendors v ON v.vendor_id = po.vendor_id
WHERE po.actual_delivery_date IS NOT NULL
GROUP BY v.vendor_id
ORDER BY late_rate DESC;


--POs Not Fully Received

SELECT
    po.po_number,
    SUM(poi.received_quantity) AS received,
    SUM(poi.quantity) AS ordered
FROM purchase_orders po
JOIN purchase_order_items poi ON poi.po_id = po.po_id
GROUP BY po.po_id
HAVING SUM(poi.received_quantity) < SUM(poi.quantity);


--Asset Depreciation Exposure (Expensive & Old)

SELECT
    asset_tag, asset_type, purchase_price, purchase_date
FROM it_assets
WHERE purchase_price > 2000
  AND purchase_date < CURRENT_DATE - INTERVAL '3 years';


--Assets Assigned to Terminated Employees

SELECT
    a.asset_tag,
    e.first_name, e.last_name
FROM it_assets a
JOIN employees e ON e.employee_id = a.assigned_to
WHERE e.employment_status = 'Terminated';


--Revenue Concentration (Top 20% Customers)

WITH ranked AS (
    SELECT
        customer_id,
        SUM(total_amount) revenue,
        NTILE(5) OVER (ORDER BY SUM(total_amount) DESC) bucket
    FROM invoices
    WHERE status IN ('Paid','Partially Paid')
    GROUP BY customer_id
)
SELECT
    SUM(revenue) FILTER (WHERE bucket = 1) AS top_20_pct_revenue,
    SUM(revenue) AS total_revenue
FROM ranked;


--Marketing ROI vs Sales Conversion

SELECT
    c.campaign_name,
    ROUND(revenue_generated / NULLIF(actual_cost,0), 2) AS roi,
    COUNT(*) FILTER (WHERE l.lead_status='Converted')::float / COUNT(*) AS conversion
FROM marketing_campaigns c
JOIN campaign_leads l ON l.campaign_id = c.campaign_id
GROUP BY c.campaign_id;






































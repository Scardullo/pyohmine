
CREATE TABLE IF NOT EXISTS "public"."address" ("address" TEXT, "phone" TEXT, "ip_addr" TEXT, "id" TEXT);

\set file_path '/home/anthony/seastar/address.csv'

TRUNCATE TABLE "public"."address" CASCADE;

COPY "public"."address"("address","phone","ip_addr","id")
FROM :'file_path'
WITH (FORMAT csv, DELIMITER ',', NULL 'NULL', QUOTE '"');
CREATE TABLE IF NOT EXISTS "public"."personnel" ("id" TEXT, "first_name" TEXT, "last_name" TEXT, "email" TEXT, "address_id" TEXT);

\set file_path '/home/anthony/seastar/personnel.csv'

TRUNCATE TABLE "public"."personnel" CASCADE;

COPY "public"."personnel"("id","first_name","last_name","email","address_id")
FROM :'file_path'
WITH (FORMAT csv, DELIMITER ',', NULL 'NULL', QUOTE '"');

-- Sample plaintext data for exercising the tokenize/reidentify UDF containers locally.
-- A real Redshift deployment would run this against actual cluster tables; this is just a
-- local stand-in so scripts/test-udf.sh has rows to read.
-- first_name/last_name/date_of_birth/zip_code exercise the UDFs (udf.sql) that have no shape in
-- full_name/email/credit_card: mask_firstname()/mask_lastname() need a standalone single-name
-- column (full_name is smart-split by mask_fullname() already), mask_dateshift() needs an
-- ISO-8601 date, mask_segmentmapping() needs a digits-only value with no separators.
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    credit_card TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    date_of_birth TEXT NOT NULL,
    zip_code TEXT NOT NULL
);

INSERT INTO customers (full_name, email, credit_card, first_name, last_name, date_of_birth, zip_code) VALUES
    ('Jane Doe', 'jane.doe@example.com', '4111-1111-1111-1111', 'Jane', 'Doe', '1985-03-14', '10001'),
    ('John Smith', 'john.smith@example.com', '5500-0000-0000-0004', 'John', 'Smith', '1990-07-22', '94105'),
    ('A B', 'ab@example.com', '3400-000000-00009', 'A', 'B', '1978-11-02', '73301');

-- Columns to hold tokens once scripts/test-udf.sh round-trips the rows above through the
-- tokenize-udf container.
CREATE TABLE customers_tokenized (
    id INTEGER PRIMARY KEY REFERENCES customers(id),
    full_name_token TEXT,
    email_token TEXT,
    credit_card_token TEXT
);

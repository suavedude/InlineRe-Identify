-- Sample plaintext data for exercising the tokenize/reidentify UDF containers locally.
-- A real Redshift deployment would run this against actual cluster tables; this is just a
-- local stand-in so scripts/test-udf.sh has rows to read.
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    credit_card TEXT NOT NULL
);

INSERT INTO customers (full_name, email, credit_card) VALUES
    ('Jane Doe', 'jane.doe@example.com', '4111-1111-1111-1111'),
    ('John Smith', 'john.smith@example.com', '5500-0000-0000-0004'),
    ('A B', 'ab@example.com', '3400-000000-00009');

-- Columns to hold tokens once scripts/test-udf.sh round-trips the rows above through the
-- tokenize-udf container.
CREATE TABLE customers_tokenized (
    id INTEGER PRIMARY KEY REFERENCES customers(id),
    full_name_token TEXT,
    email_token TEXT,
    credit_card_token TEXT
);

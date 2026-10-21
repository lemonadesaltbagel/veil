-- Realistic application-shaped PII on top of Chinook (PostgreSQL).
-- Exercises: JSONB nesting, text[] arrays, citext, inet, ambiguous column names
-- (only a COMMENT says it's PII), FK-linked person tables, schema-per-tenant,
-- free text, event payloads, and a view that must not be double-counted.
\c chinook
CREATE EXTENSION IF NOT EXISTS citext;
DROP SCHEMA IF EXISTS app CASCADE;
DROP SCHEMA IF EXISTS tenant_acme CASCADE;
CREATE SCHEMA app;
CREATE SCHEMA tenant_acme;

CREATE TABLE app.accounts (
    id              serial PRIMARY KEY,
    customer_id     int NOT NULL UNIQUE REFERENCES public.customer (customer_id),
    login           citext UNIQUE NOT NULL,
    contact         text,          -- ambiguous name; holds a personal email
    profile         jsonb NOT NULL,
    aliases         text[],
    last_login_ip   inet,
    password_hash   text,
    created_at      timestamptz DEFAULT now()
);
COMMENT ON COLUMN app.accounts.contact IS 'pii:email - secondary contact address';

INSERT INTO app.accounts (customer_id, login, contact, profile, aliases, last_login_ip, password_hash)
SELECT c.customer_id,
       lower(translate(c.first_name, 'áàâãäçéèêëíîïñóôõöúüøåæšžčřłńśźżß ', 'aaaaaceeeeiiinoooouuoaaszcrlnszzs_')) || '.' || c.customer_id,
       lower(translate(c.first_name, 'áàâãäçéèêëíîïñóôõöúüøåæšžčřłńśźżß ', 'aaaaaceeeeiiinoooouuoaaszcrlnszzs_')) || c.customer_id || '@mailbox.org',
       jsonb_build_object(
           'name',   jsonb_build_object('given', c.first_name, 'family', c.last_name),
           'emails', jsonb_build_array(c.email),
           'phones', jsonb_build_array(jsonb_build_object('type', 'mobile', 'number', c.phone)),
           'address', jsonb_build_object('street', c.address, 'city', c.city, 'country', c.country),
           'prefs',  jsonb_build_object('theme', 'dark', 'newsletter', c.customer_id % 2 = 0, 'lang', 'en')),
       ARRAY['cust' || c.customer_id || '_' || lower(left(c.last_name, 3))],
       ('85.' || (c.customer_id * 3 % 250 + 1) || '.' || (c.customer_id * 7 % 250 + 1) || '.' || (c.customer_id % 250 + 1))::inet,
       md5(c.email)
FROM public.customer c;

CREATE TABLE app.support_tickets (
    id          serial PRIMARY KEY,
    account_id  int REFERENCES app.accounts (id),
    subject     text,
    body        text            -- free text: mentions people by name/email
);
INSERT INTO app.support_tickets (account_id, subject, body)
SELECT a.id, 'Billing question',
       'Hi, this is ' || c.first_name || ' ' || c.last_name || '. Please reply to ' || c.email ||
       ' or call ' || coalesce(c.phone, 'n/a') || '. Thanks!'
FROM app.accounts a JOIN public.customer c USING (customer_id)
WHERE c.customer_id <= 10;

CREATE TABLE app.events (
    id       bigserial PRIMARY KEY,
    type     text,
    payload  jsonb               -- PII nested in event payloads, not keyed by person
);
INSERT INTO app.events (type, payload)
SELECT 'login', jsonb_build_object('actor', jsonb_build_object('email', c.email, 'ip', '85.' || c.customer_id || '.1.9'),
                                   'ua', 'Mozilla/5.0', 'ok', true)
FROM public.customer c WHERE c.customer_id % 3 = 0;

CREATE VIEW app.v_customer_contacts AS
SELECT c.customer_id, c.first_name || ' ' || c.last_name AS full_name, c.email FROM public.customer c;

-- schema-per-tenant SaaS layout
CREATE TABLE tenant_acme.users (
    user_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    handle      text NOT NULL,
    work_email  text NOT NULL,
    display_name text,
    mobile      text
);
INSERT INTO tenant_acme.users (handle, work_email, display_name, mobile) VALUES
    ('hkowalski',  'hanna.kowalski@acme-industries.pl', 'Hanna Kowalski', '+48 601 234 567'),
    ('tobias.r',   'tobias.reinhardt@acme-industries.pl', 'Tobias Reinhardt', '+49 151 2345 6789'),
    ('mei_lin',    'mei.lin@acme-industries.pl', 'Mei Lin', '+86 138 0013 8000');

-- column names carry no meaning: only value sampling can classify c1
CREATE TABLE app.newsletter_imports (id serial PRIMARY KEY, c1 text, c2 text, imported_at timestamptz DEFAULT now());
INSERT INTO app.newsletter_imports (c1, c2)
SELECT lower(c.first_name) || '.' || lower(c.last_name) || '@newsletter-list.net', 'opt-in' FROM public.customer c;

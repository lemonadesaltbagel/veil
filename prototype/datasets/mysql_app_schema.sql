-- MySQL/MariaDB-specific PII shapes on top of Chinook.
USE Chinook;
DROP TABLE IF EXISTS app_users;
CREATE TABLE app_users (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    customer_id  INT UNIQUE,
    settings     JSON,                                  -- MariaDB: LONGTEXT + JSON_VALID check
    email_lower  VARCHAR(80) AS (LOWER(JSON_UNQUOTE(JSON_EXTRACT(settings, '$.contact.email')))) STORED,
    note         VARCHAR(200) COMMENT 'pii:name',
    FOREIGN KEY (customer_id) REFERENCES Customer (CustomerId)
);
INSERT INTO app_users (customer_id, settings, note)
SELECT CustomerId,
       JSON_OBJECT('contact', JSON_OBJECT('email', Email, 'phone', Phone), 'theme', 'dark',
                   'devices', JSON_ARRAY(JSON_OBJECT('ip', CONCAT('91.', CustomerId, '.20.7')))),
       CONCAT(FirstName, ' ', LastName)
FROM Customer;

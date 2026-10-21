`pg_anonymizer_identifier.csv` — column-name dictionary from PostgreSQL Anonymizer
(https://gitlab.com/dalibo/postgresql_anonymizer, data/identifier.csv).
Copyright (c) 2018-2020, DALIBO SCOP. The PostgreSQL License (permissive).
veil maps only some categories to its kinds; see veil/sources/core.py `ANON_CATEGORY`.

`words.txt.gz`: the lower-case entries of Webster's Second International Dictionary word list
(`web2`, 1934, public domain, as distributed with BSD and macOS in `/usr/share/dict`). Used to
keep standalone name parts that are ordinary words (`Code`, `Read`, `Mark`) from being seeded.

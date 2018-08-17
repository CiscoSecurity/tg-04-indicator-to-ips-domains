### Indicator to IPs and Domains

The script does the following:
1. Query Threat Grid for the existance of each hash in the provided list
2. If the hash exists collect associated samples and fetch the network streams for each sample
3. Extract the unique public IPs and Domains from each samples
4. Output the informaiton to the console and to a file in a RESULTS directory

### Usage
The script takes a file as a parameter. The file should have one hash (MD5, SHA1, SHA256) per line.
```
python hash_query.py hashlist.txt
```

#### Example script output
```
Line 1 of 1 is a Winner! - 7bdc23cc435305da225148b643fc5273a0bf4e227327e15309fe8d5d98c12c20

Found 1 out of 1 hashes in the system

Found 30 samples from 1 hashes:

Found 9 IP Addresses:
  34.195.37.78
  52.20.74.226
  52.22.211.38
  52.26.195.230
  52.173.193.166
  54.164.91.17
  54.210.188.78
  194.150.168.74
  216.239.36.21

Found 5 domains:
  dpckd2ftmf7lelsa.jjeyd2u37an30.com
  dpckd2ftmf7lelsa.s24f53mnd7w31.com
  dpckd2ftmf7lelsa.tor2web.blutmagie.de
  dpckd2ftmf7lelsa.tor2web.fi
  ipinfo.io
```

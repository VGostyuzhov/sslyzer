# SSLyzer
## Installation:
```
pip install -r requirements.txt
chmod u+x sslyzer.py
```

## Usage:
* Scan single server, print result to stdout:
```
sslyzer.py -w example.com
```

* Scan multiple servers from file hostnames.txt. Save result to xlsx file in Reports folder:
``` 
./sslyzer.py -f hostnames.txt -x example_resut.xlsx
```

* Scan multiple servers, save to xlsx file, wide output to stdout:
```
./sslyzer.py -f hostnames.txt -x example_resut.xlsx -w
```

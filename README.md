![testssl2xlsx](images/testssl2xlsx.png)
# testssl2xlsx
[![Language](https://img.shields.io/badge/Lang-Python-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)](https://opensource.org/licenses/Apache-2.0)

This script parses `testssl pretty JSON` scans results into `Excel` tables (`.xlsx`) to facilitate the reporting process of penetration tests, especially useful when dealing with big scopes. Having scans results organised in `Excel` tables also allow customers and testers to use `Excel` strong filtering capabilities. 

The following worksheets are generated:
* `Host vs Protocols`
* `Host vs Protocol`
* `Host vs Vulnerabilities`
* `Host vs Vulnerability`

## Installation
```
$ git clone https://github.com/AresS31/testssl2xlsx
# python -m pip install -r testssl2xlsx/requirements.txt
 ```

## Usage
```
$ python testssl2xlsx.py [-h]
                   [-f {beast,breach,crime,freak,logjam,lucky13,poodle_ssl,rc4,sweet32} [{beast,breach,crime,freak,logjam,lucky13,poodle_ssl,rc4,sweet32} ...]]
                   -iJ INPUT_FILE [-oX OUTPUT_FILE] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -f {beast,breach,crime,freak,logjam,lucky13,poodle_ssl,rc4,sweet32} [{beast,breach,crime,freak,logjam,lucky13,poodle_ssl,rc4,sweet32} ...], --filters {beast,breach,crime,freak,logjam,lucky13,poodle_ssl,rc4,sweet32} [{beast,breach,crime,freak,logjam,lucky13,poodle_ssl,rc4,sweet32} ...]
                        vulnerability/ies to process
  -iJ INPUT_FILE, --input-json INPUT_FILE
                        pretty JSON file containing the testssl results
  -oX OUTPUT_FILE, --output-xlsx OUTPUT_FILE
                        XLSX file containing the output results
  -v, --verbose         enable output verbosity
```

## Possible Improvements
- [ ] Adding new features.
- [ ] Source code optimisation.

## Licenses
### testssl2xlsx
Copyright (C) 2017 Alexandre Teyar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. 

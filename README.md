<p align="center">
  <img alt="logo" src="images/testssl2xlsx.png" height="200">
  <p align="center">
      <a href="https://www.python.org"><img alt="lang" src="https://img.shields.io/badge/Lang-Python-blue.svg"></a>
      <a href="https://opensource.org/licenses/Apache-2.0"><img alt="license" src="https://img.shields.io/badge/License-Apache%202.0-red.svg"></a>
      <br>
      <img alt="bitcoin" src="https://img.shields.io/badge/Bitcoin-15aFaQaW9cxa4tRocax349JJ7RKyj7YV1p-yellow.svg">
      <img alt="bitcoin cash" src="https://img.shields.io/badge/Bitcoin%20Cash-qqez5ed5wjpwq9znyuhd2hdg86nquqpjcgkm3t8mg3-yellow.svg">
      <img alt="ether" src="https://img.shields.io/badge/Ether-0x70bC178EC44500C17B554E62BC31EA2B6251f64B-yellow.svg">
  </p>
</p>

# This project has now been deprecated. Its functionality has been incorporated into [pentest2xlsx](https://github.com/AresS31/pentest2xlsx).

Parse `testssl` scans results (in a `JSON` format) into `Excel` tables to facilitate the reporting process of penetration tests, especially useful when dealing with large scopes. Having scans results organised in `Excel` tables also allow customers and testers to use `Excel` powerful filtering capabilities.

The following Excel worksheets are generated:
* `Host vs Certificate`
* `Host vs Certificates`
* `Host vs Protocol`
* `Host vs Protocols`
* `Host vs Vulnerability`
* `Host vs Vulnerabilities`

## Installation
```
$ git clone https://github.com/AresS31/testssl2xlsx
# python -m pip install -r testssl2xlsx/requirements.txt
 ```

## Usage
```
testssl2xlsx.py [-h] -iJ INPUT_FILES [INPUT_FILES ...]
                [-oX OUTPUT_FILE] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -iJ INPUT_FILES [INPUT_FILES ...], --input-json INPUT_FILES [INPUT_FILES ...]
                        input from testssl file(s) in JSON format
  -oX OUTPUT_FILE, --output-xlsx OUTPUT_FILE
                        output results to a specified <OUTPUT_FILE> in XLSX
                        format
  -v, --verbose         increase verbosity level
```

## Example
1. Generate the `testssl` input file with:

`$ testssl --jsonfile-pretty testssl-results.json --quiet --nodns none --parallel --server-defaults --protocols --vulnerable --file ../nmap/SYN-*.gnmap`

2. Run `testssl2xlsx` with the testssl `JSON` file generated in the previous step:

`$ python testssl2xlsx.py -iJ testssl-results.json`

## Possible Improvements
- [ ] Adding new features, such as --protocols filtering.
- [ ] Enforce the correct file extensions (input file(s) must be .json, output file must be .xlsx)
- [ ] Reconfigure the logging module to load its settings with a configuration file
- [ ] Implement support for directory input rather than individual files.
- [ ] Source code optimisation.

## Donations
* Via Bitcoin      : **15aFaQaW9cxa4tRocax349JJ7RKyj7YV1p**
* Via Bitcoin Cash : **qqez5ed5wjpwq9znyuhd2hdg86nquqpjcgkm3t8mg3**
* Via Ether        : **0x70bC178EC44500C17B554E62BC31EA2B6251f64B**

## License(s)
### testssl2xlsx
Copyright 2017 - 2019 Alexandre Teyar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. 

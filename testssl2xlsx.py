#!/usr/bin/env python3
#    Copyright (C) 2017 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this output_file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

import argparse
import json
import logging
import sys
import time
import xlsxwriter

# custom levels for the logging lib
RESULT = 21
# add or remove entries from the lists below in order to enable/disable
# reporting for the selected entries
protocols = sorted([
    "sslv2",
    "sslv3",
    "tls1",
    "tls1_1",
    "tls1_2",
    "tls1_3"
])
vulnerabilities = sorted([
    "beast",
    "breach",
    "crime_tls",
    "fallback_scsv",
    "freak",
    "logjam",
    "lucky13",
    "poodle_ssl",
    "rc4",
    "robot",
    "secure_client_renego",
    "sweet32"
])


def parse_args():
    """ Parse and validate the command line
    """
    parser = argparse.ArgumentParser(
        description=(
            "Parse testssl pretty JSON files into an Excel spreadsheet for "
            "quicker and easier reporting"
        )
    )

    parser.add_argument(
        "-f",
        "--filters",
        choices=vulnerabilities,
        default=vulnerabilities,
        dest="filters",
        help="vulnerability/ies to process",
        nargs='+',
        required=False,
        type=str
    )

    parser.add_argument(
        "-iJ",
        "--input-json",
        dest="input_file",
        help="pretty JSON file containing the testssl results",
        required=True,
        type=argparse.FileType('r')
    )

    parser.add_argument(
        "-oX",
        "--output-xlsx",
        dest="output_file",
        help="XLSX file containing the output results",
        required=False,
        type=str
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_const",
        const=logging.DEBUG,
        default=logging.INFO,
        dest="loglevel",
        help="enable output verbosity",
        required=False
    )

    return parser.parse_args()


def write_table(worksheet, table_headers, table_data):
    """ Create an Excel worksheet containing the 'table_headers'
        and 'table_data' dataset
    """
    column_count = 0
    row_count = 0
    table_column_count = len(table_headers) - 1
    table_row_count = len(table_data)

    logging.debug("{}".format(table_headers))
    logging.debug("{}".format(table_data))

    worksheet.add_table(
        row_count,
        column_count,
        table_row_count,
        table_column_count,
        {
            "banded_rows": True,
            "columns": table_headers,
            "data": table_data,
            "first_column": True,
            "style": "Table Style Medium 1"
        }
    )


def parse_host_protocols(workbook, data):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"}
    ]

    for protocol in protocols:
        table_headers.append({"header": protocol.upper()})

    for values in data["scanResult"]:
        d = {
            "Host IP": values["ip"],
            "Port": int(values["port"])
        }

        for protocol in values["protocols"]:
            if protocol["id"].upper() in [x.upper() for x in protocols]:
                if protocol["finding"] == "offered":
                    d[protocol["id"].upper()] = "YES"
                else:
                    d[protocol["id"].upper()] = "NO"

        # putting the values at the right index
        data = []
        headers = [x["header"] for x in table_headers]

        for header in headers:
            if header in d.keys():
                data.insert(headers.index(header), d.get(header))
            else:
                data.insert(headers.index(header), "N/A")

        table_data.append(data)

    worksheet = workbook.add_worksheet("Host vs Protocols")
    write_table(worksheet, table_headers, table_data)


def parse_host_protocol(workbook, data):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"},
        {"header": "Supported Protocol"},
        {"header": "Severity"}
    ]

    for values in data["scanResult"]:
        for protocol in values["protocols"]:
            if protocol["id"].upper() in [x.upper() for x in protocols]:
                if protocol["finding"] == "offered":
                    table_data.append(
                        [
                            values["ip"],
                            int(values["port"]),
                            protocol["id"].upper(),
                            protocol["severity"]
                        ]
                    )

    worksheet = workbook.add_worksheet("Host vs Protocol")
    write_table(worksheet, table_headers, table_data)


def parse_host_vulns(workbook, data, filters):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"}
    ]

    for vulnerability in filters:
        table_headers.append({"header": vulnerability.upper()})

    for values in data["scanResult"]:
        d = {
            "Host IP": values["ip"],
            "Port": int(values["port"])
        }

        for vulnerability in values["vulnerabilities"]:
            if vulnerability["id"].upper() in [x.upper() for x in filters]:
                d[vulnerability["id"].upper()] = vulnerability["severity"]

        # putting the values at the right index
        data = []
        headers = [x["header"] for x in table_headers]

        for header in headers:
            if header in d.keys():
                data.insert(headers.index(header), d.get(header))
            else:
                data.insert(headers.index(header), "N/A")

        table_data.append(data)

    worksheet = workbook.add_worksheet("Host vs Vulnerabilities")
    write_table(worksheet, table_headers, table_data)


def parse_host_vuln(workbook, data, filters):
    table_data = []
    vcenter = workbook.add_format({"valign": "vcenter"})
    table_headers = [
        {
            "header": "Host IP",
            "format": vcenter
        },
        {
            "header": "Port",
            "format": vcenter
        },
        {
            "header": "Vulnerability",
            "format": vcenter
        },
        {
            "header": "Severity",
            "format": vcenter
        },
        {
            "header": "CVE",
            "format": workbook.add_format(
                {
                    "text_wrap": 1,
                    "valign": "top"
                }
            )
        },
        {
            "header": "Information",
            "format": vcenter
        },
    ]

    for values in data["scanResult"]:
        for vulnerability in values["vulnerabilities"]:
            if vulnerability["id"].upper() in [x.upper() for x in filters]:
                table_data.append(
                    [
                        values["ip"],
                        int(values["port"]),
                        vulnerability["id"].upper(),
                        vulnerability["severity"],
                        # avoid to raise KeyError exceptions for entries with
                        # no CVE defined
                        # replace comma and space with return line to prevent
                        # super wide cells
                        vulnerability.get("cve", "N/A").
                        replace(", ", "\r\n").replace(" ", "\r\n"),
                        vulnerability["finding"]
                    ]
                )

    worksheet = workbook.add_worksheet("Host vs Vulnerability")
    write_table(worksheet, table_headers, table_data)


def main():
    try:
        args = parse_args()

        logging.addLevelName(RESULT, "RESULT")
        logging.basicConfig(
            format="%(levelname)-8s %(message)s",
            handlers=[
                logging.StreamHandler(sys.stdout)
            ],
            level=args.loglevel
        )

        if args.output_file:
            output_file = "{}.xlsx".format(args.output_file)
        else:
            output_file = "testssl-results_{}.xlsx".format(
                time.strftime("%Y%m%d-%H%M%S")
            )

        # variables summary
        logging.info("pretty JSON input file: {}".format(args.input_file.name))
        logging.info("XLSX output file: {}".format(output_file))
        logging.info("vulnerability/ies to process: {}".format(
            sorted(args.filters)
        ))

        data = json.load(args.input_file)

        workbook = xlsxwriter.Workbook("{}".format(output_file))

        logging.log(
            RESULT,
            "generating 'Host vs Protocols' worksheet..."
        )
        parse_host_protocols(workbook, data)

        logging.log(
            RESULT,
            "generating 'Host vs Protocol' worksheet..."
        )
        parse_host_protocol(workbook, data)

        logging.log(
            RESULT,
            "generating 'Host vs Vulnerabilities' worksheet..."
        )
        parse_host_vulns(workbook, data, sorted(args.filters))

        logging.log(
            RESULT,
            "generating 'Host vs Vulnerability' worksheet..."
        )
        parse_host_vuln(workbook, data, sorted(args.filters))

        workbook.close()
    except KeyboardInterrupt:
        logging.exception("'CTRL+C' pressed, exiting...")


if __name__ == "__main__":
    main()

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

from collections import OrderedDict

# custom levels for the logging lib
RESULT = 21


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
        choices=[
            "beast",
            "breach",
            "crime",
            "freak",
            "logjam",
            "lucky13",
            "poodle_ssl",
            "rc4",
            "sweet32"
        ],
        default=[
            "beast",
            "breach",
            "crime",
            "freak",
            "logjam",
            "lucky13",
            "poodle_ssl",
            "rc4",
            "sweet32"
        ],
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


def write_worksheet(workbook, worksheet, table_headers, table_data):
    """ Create an Excel worksheet containing the 'table_headers'
        and 'table_data' dataset
    """
    if not table_data:
        logging.warning("'{}' could not be created".format(
            worksheet
        ))
        return
    else:
        worksheet = workbook.add_worksheet("{}".format(worksheet))

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

        worksheet.freeze_panes(0, 1)


def parse_host_protocols(workbook, data):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"},
        {"header": "SSLv2"},
        {"header": "SSLv3"},
        {"header": "TLSv1.0"},
        {"header": "TLSv1.1"},
        {"header": "TLSv1.2"},
        {"header": "TLSv1.3"}
    ]

    for values in data["scanResult"]:
        host_ip = values["ip"]
        port = values["port"]
        sslv2 = "N/A"
        sslv3 = "N/A"
        tlsv1 = "N/A"
        tlsv1_1 = "N/A"
        tlsv1_2 = "N/A"
        tlsv1_3 = "N/A"

        for protocol in values["protocols"]:
            if protocol["id"] == "sslv2":
                if "is offered" in protocol["finding"]:
                    sslv2 = "YES"
                else:
                    sslv2 = "NO"
            elif protocol["id"] == "sslv3":
                if "is offered" in protocol["finding"]:
                    sslv3 = "YES"
                else:
                    sslv3 = "NO"
            elif protocol["id"] == "tls1":
                if "is offered" in protocol["finding"]:
                    tlsv1 = "YES"
                else:
                    tlsv1 = "NO"
            elif protocol["id"] == "tls1_1":
                if "is offered" in protocol["finding"]:
                    tlsv1_1 = "YES"
                else:
                    tlsv1_1 = "NO"
            elif protocol["id"] == "tls1_2":
                if "is offered" in protocol["finding"]:
                    tlsv1_2 = "YES"
                else:
                    tlsv1_2 = "NO"
            elif protocol["id"] == "tls1_3":
                if "is offered" in protocol["finding"]:
                    tlsv1_3 = "YES"
                else:
                    tlsv1_3 = "NO"

        table_data.append(
            [
                host_ip,
                int(port),
                sslv2,
                sslv3,
                tlsv1,
                tlsv1_1,
                tlsv1_2,
                tlsv1_3
            ]
        )

    write_worksheet(workbook, "Host vs Protocols",
                    table_headers, table_data)


def parse_host_protocol(workbook, data):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"},
        {"header": "Protocol"}
    ]

    for values in data["scanResult"]:
        host_ip = values["ip"]
        port = values["port"]
        protocol_version = "N/A"

        for protocol in values["protocols"]:
            if protocol["id"] == "sslv2":
                protocol_version = "SSLv2"
            elif protocol["id"] == "sslv3":
                protocol_version = "SSLv3"
            elif protocol["id"] == "tls1":
                protocol_version = "TLSv1"
            elif protocol["id"] == "tls1_1":
                protocol_version = "TLSv1.1"
            elif protocol["id"] == "tls1_2":
                protocol_version = "TLSv1.2"
            elif protocol["id"] == "tls1_3":
                protocol_version = "TLSv1.3"

            table_data.append(
                [
                    host_ip,
                    int(port),
                    protocol_version
                ]
            )

    write_worksheet(workbook, "Host vs Protocol",
                    table_headers, table_data)


def parse_host_vulns(workbook, data, filters):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"}
    ]

    for vulnerability in filters:
        table_headers.append({"header": vulnerability.upper()})

    for values in data["scanResult"]:
        host_ip = values["ip"]
        port = values["port"]
        data = [
                host_ip,
                int(port)
        ]
        vulns = {}

        for cipherTest in values["cipherTests"]:
            if cipherTest["id"] in filters:
                vulns[cipherTest["id"]] = cipherTest["severity"]

        # this step is necessary to alphabetically sort the vulnerabilities
        # in order to have the severities matching the right columns
        for key, value in sorted(vulns.items()):
            data.append(value)

        table_data.append(data)

    write_worksheet(workbook, "Host vs Vulnerabilities",
                    table_headers, table_data)


def parse_host_vuln(workbook, data, filters):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"},
        {"header": "Vulnerability"},
        {"header": "Severity"},
        {"header": "CVE"},
        {"header": "Information"},
    ]

    for values in data["scanResult"]:
        host_ip = values["ip"]
        port = values["port"]

        for cipherTest in values["cipherTests"]:
            if cipherTest["id"] in filters:
                table_data.append(
                    [
                        host_ip,
                        int(port),
                        cipherTest["id"].upper(),
                        cipherTest["severity"],
                        cipherTest["cve"],
                        cipherTest["finding"]
                    ]
                )

    write_worksheet(workbook, "Host vs Vulnerability",
                    table_headers, table_data)


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

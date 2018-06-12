#!/usr/bin/env python3
#    Copyright 2017 - 2018 Alexandre Teyar

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

# add or remove entries from the lists below in order to enable/disable
# reporting for the selected entries - respect the case -
certificates = {
    "cert_chain_of_trust": {
        "name": "Chain of Trust"
    },
    "cert_expiration_status": {
        "name": "Expired"
    },
    "cert_signatureAlgorithm": {
        "name": "Weak Hashing Algorithm"
    },
    "cert_trust": {
        "name": "Trust"
    }
}
protocols = sorted([
    "SSLv2",
    "SSLv3",
    "TLS1",
    "TLS1_1",
    "TLS1_2",
    "TLS1_3"
])
vulnerabilities = {
    "BEAST": {
        "name": "BEAST"
    },
    "BREACH": {
        "name": "BREACH"
    },
    "CRIME_TLS": {
        "name": "CRIME"
    },
    # "fallback_SCSV": {
    #     "name": "Fallback SCSV"
    # },
    "FREAK": {
        "name": "FREAK"
    },
    "LOGJAM": {
        "name": "Logjam"
    },
    "LUCKY13": {
        "name": "Lucky13"
    },
    "POODLE_SSL": {
        "name": "POODLE"
    },
    "RC4": {
        "name": "RC4"
    },
    "ROBOT": {
        "name": "ROBOT"
    },
    # "secure_client_renego": {
    #     "name": "Secure Client Renegotiation"
    # },
    "SWEET32": {
        "name": "Sweet32"
    }
}


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
        "-iJ",
        "--input-json",
        dest="input_file",
        help="JSON file (in pretty format) containing the testssl results",
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
        help="enable verbosity",
        required=False
    )

    return parser.parse_args()


def insert(headers, d):
    """ Insert values at the appropriate index
    """
    data = ["N/A"] * len(headers)

    for key, values in d.items():
        if isinstance(values, dict):
            data[headers.index(values["name"])] = values.get("severity")
        else:
            data[headers.index(key)] = values

    return data


def draw_table(worksheet, table_headers, table_data):
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


def parse_host_certificate(workbook, data):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"},
        {"header": "Vulnerability"},
        {"header": "Severity"},
        {"header": "Information"}
    ]

    try:
        for values in data["scanResult"]:
            for serverDefault in values["serverDefaults"]:
                if serverDefault["id"] in certificates.keys():
                    table_data.append(
                        [
                            values["ip"],
                            int(values["port"]),
                            certificates[serverDefault["id"]]["name"],
                            serverDefault["severity"],
                            serverDefault["finding"]
                        ]
                    )

        worksheet = workbook.add_worksheet("Host vs Certificate")
        draw_table(worksheet, table_headers, table_data)
    except KeyError as e:
        logging.exception("KeyError - {}".format(e))


def parse_host_certificates(workbook, data):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"}
    ]

    for values in certificates.values():
        table_headers.append({"header": values["name"]})

    try:
        for values in data["scanResult"]:
            d = {
                "Host IP": values["ip"],
                "Port": int(values["port"])
            }

            for serverDefault in values["serverDefaults"]:
                if serverDefault["id"] in certificates.keys():
                    d[serverDefault["id"]] = {
                        "name": certificates[serverDefault["id"]]["name"],
                        "severity": serverDefault["severity"]
                    }

            table_data.append(insert([x["header"] for x in table_headers], d))

        worksheet = workbook.add_worksheet("Host vs Certificates")
        draw_table(worksheet, table_headers, table_data)
    except KeyError as e:
        logging.exception("KeyError - {}".format(e))


def parse_host_protocol(workbook, data):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"},
        {"header": "Supported Protocol"},
        {"header": "Severity"}
    ]

    try:
        for values in data["scanResult"]:
            for protocol in values["protocols"]:
                if protocol["id"] in protocols:
                    if protocol["finding"] == "offered":
                        table_data.append(
                            [
                                values["ip"],
                                int(values["port"]),
                                protocol["id"],
                                protocol["severity"]
                            ]
                        )

        worksheet = workbook.add_worksheet("Host vs Protocol")
        draw_table(worksheet, table_headers, table_data)
    except KeyError as e:
        logging.exception("KeyError - {}".format(e))


def parse_host_protocols(workbook, data):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"}
    ]

    for protocol in protocols:
        table_headers.append({"header": protocol})

    try:
        for values in data["scanResult"]:
            d = {
                "Host IP": values["ip"],
                "Port": int(values["port"])
            }

            for protocol in values["protocols"]:
                if protocol["id"] in protocols:
                    if protocol["finding"] == "offered":
                        d[protocol["id"]] = "YES"
                    else:
                        d[protocol["id"]] = "NO"

            table_data.append(insert([x["header"] for x in table_headers], d))

        worksheet = workbook.add_worksheet("Host vs Protocols")
        draw_table(worksheet, table_headers, table_data)
    except KeyError as e:
        logging.exception("KeyError - {}".format(e))


def parse_host_vulnerability(workbook, data):
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
        }
    ]

    try:
        for values in data["scanResult"]:
            for vulnerability in values["vulnerabilities"]:
                if vulnerability["id"] in vulnerabilities.keys():
                    table_data.append(
                        [
                            values["ip"],
                            int(values["port"]),
                            vulnerabilities[vulnerability["id"]]["name"],
                            vulnerability["severity"],
                            # avoid to raise KeyError exceptions for entries
                            # with no CVE defined replace space with Windows'
                            # return line to prevent super wide cells
                            vulnerability.get("cve", "N/A").replace(
                                " ", "\r\n"),
                            vulnerability["finding"]
                        ]
                    )

        worksheet = workbook.add_worksheet("Host vs Vulnerability")
        draw_table(worksheet, table_headers, table_data)
    except KeyError as e:
        logging.exception("KeyError - {}".format(e))


def parse_host_vulnerabilities(workbook, data):
    table_data = []
    table_headers = [
        {"header": "Host IP"},
        {"header": "Port"}
    ]

    for values in vulnerabilities.values():
        table_headers.append({"header": values["name"]})

    try:
        for values in data["scanResult"]:
            d = {
                "Host IP": values["ip"],
                "Port": int(values["port"])
            }

            for vulnerability in values["vulnerabilities"]:
                if vulnerability["id"] in vulnerabilities.keys():
                    d[vulnerability["id"]] = {
                        "name": vulnerabilities[vulnerability["id"]]["name"],
                        "severity": vulnerability["severity"]
                    }

            table_data.append(insert([x["header"] for x in table_headers], d))

        worksheet = workbook.add_worksheet("Host vs Vulnerabilities")
        draw_table(worksheet, table_headers, table_data)
    except KeyError as e:
        logging.exception("KeyError - {}".format(e))


def main():
        args = parse_args()

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
                time.strftime("%Y%m%d-%H%M%S"))

        # variables summary
        logging.info("pretty JSON input file(s): {}".format(
            args.input_file.name))
        logging.info("XLSX output file: {}".format(output_file))
        logging.info("certificate issue(s) to process: {}".format(
            sorted(certificates.keys())))
        logging.info("protocol(s) to process: {}".format(protocols))
        logging.info("vulnerability/ies to process: {}".format(
            sorted(vulnerabilities.keys())))

        data = json.load(args.input_file)

        workbook = xlsxwriter.Workbook("{}".format(output_file))

        logging.info("generating worksheet 'Host vs Certificate'...")
        parse_host_certificate(workbook, data)

        logging.info("generating worksheet 'Host vs Certificates'...")
        parse_host_certificates(workbook, data)

        logging.info("generating worksheet 'Host vs Protocol'...")
        parse_host_protocol(workbook, data)

        logging.info("generating worksheet 'Host vs Protocols'...")
        parse_host_protocols(workbook, data)

        logging.info("generating worksheet 'Host vs Vulnerability'...")
        parse_host_vulnerability(workbook, data)

        logging.info("generating worksheet 'Host vs Vulnerabilities'...")
        parse_host_vulnerabilities(workbook, data)

        workbook.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        logging.exception("{}".format(e))

#!/usr/bin/env python3

import argparse
import re
import subprocess
import sys

OK = 0
WARN = 1
CRITICAL = 2

CONTAINER_NAME = "analyticsdatabase_cassandra_1"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check AnalyticDB Cassandra using nodetool"
    )
    parser.add_argument("-c", "--command", default="status")
    parser.add_argument(
        "-f",
        "--input-file",
        dest="input_file",
        help="read input content from this file",
    )
    return parser.parse_args()


def run_nodetool(nodetool_cmd):
    """
    Runs nodetool using the provided command via docker exec
    """
    try:
        sh_cmd = "nodetool -p $CASSANDRA_JMX_LOCAL_PORT {}".format(nodetool_cmd)
        cmd = ["sudo", "docker", "exec", CONTAINER_NAME, "/bin/sh", "-c", sh_cmd]
        output = subprocess.check_output(cmd).decode("UTF-8")
    except subprocess.CalledProcessError as err:
        message = (
            "CRITICAL: Could not execute nodetool"
            " return code: {} cmd: {} output: {}".format(
                err.returncode, err.cmd, err.output
            )
        )
        print(message)
        sys.exit(CRITICAL)
    return output


def check_nodetool_status(output, warning_level=1, critical_level=2):
    """
    Parses the output of 'nodetool status' (example below), and
    compares the number of nodes down with the failure criteria

    Datacenter: datacenter1
    =======================
    Status=Up/Down
    |/ State=Normal/Leaving/Joining/Moving
    --  Address        Load       Tokens       Owns (effective)  Host ID                               Rack
    UN  172.20.40.73   9.09 GiB   256          63.2%             59fb5a25-6b29-437b-a39a-1d0e71257b2a  rack1
    UN  172.20.40.11   10.77 GiB  256          67.0%             d09a7a73-8553-41c8-b59b-ad9be8361de7  rack1
    UN  172.20.40.139  12.65 GiB  256          69.8%             c9dd65bf-1e4f-45d6-b0dc-d2eae422b15a  rack1
    """

    # skip the header lines using the marker as reference (do not assume # lines)
    node_lines = output[output.find("-- ") :].splitlines()[1:]
    number_down_nodes = sum(1 for line in node_lines if line.startswith("D"))

    # compare with the failure criteria
    if number_down_nodes >= critical_level:
        return (CRITICAL, "CRITICAL: {} nodes down".format(number_down_nodes))
    elif number_down_nodes >= warning_level:
        return (WARN, "WARNING: 1 node down")
    return (OK, "OK: All nodes UP")


def check_nodetool_compactionstats(output, warning_level=1, critical_level=20):
    """
    Parses the output of 'nodetool compactionstat' (example below), and
    compares the number of pending compaction tasks with the failure criteria

    pending tasks: 7
    compaction type  keyspace   column family   completed      total           unit   progress
    Compaction       Test       Message         161257707087   2475323941809   bytes  6.51%
    """

    match = re.search("pending tasks: (\d+)", output)

    if not match:
        message = "CRITICAL: Could not parse nodetool output: {}".format(output[:50])
        print(message)
        sys.exit(CRITICAL)

    pending_tasks = int(match.groups()[0])

    # compare with the failure criteria
    if pending_tasks >= critical_level:
        return (CRITICAL, "CRITICAL: {} compaction tasks pending".format(pending_tasks))
    elif pending_tasks >= warning_level:
        return (WARN, "WARNING: {} compaction tasks pending".format(pending_tasks))
    return (OK, "OK: No pending compaction tasks")


def run_check():
    args = parse_args()

    # if we get an input file read it, useful for testing
    if args.input_file:
        with open(args.input_file, mode="r", encoding="utf8") as f:
            output = f.read()
    else:  # otherwise query using nodetool
        output = run_nodetool(args.command)

    if args.command == "status":
        result, msg = check_nodetool_status(output)
    elif args.command == "compactionstats":
        result, msg = check_nodetool_compactionstats(output)

    print(msg)
    sys.exit(result)


if __name__ == "__main__":
    run_check()

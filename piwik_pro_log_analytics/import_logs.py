#!/usr/bin/python
#
# Piwik PRO - take control of your data
#
# @link https://piwik.pro/
# @license https://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
# @version $Id$
#
# For more info see: https://github.com/PiwikPRO/log-analytics/


import sys

if sys.version_info[0] != 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 6):
    print("The log importer does not support older python versions.")
    print("Please use Python 3.6+")
    sys.exit(1)

import argparse
import base64
import bz2
import collections
import copy
import datetime
import fnmatch
import glob
import gzip
import http.client
import inspect
import itertools
import json
import logging
import os
import os.path
import queue
import re
import socket
import ssl
import sys
import textwrap
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

# Avoid "got more than 100 headers" error
http.client._MAXHEADERS = 1000


# Constants

# import_logs.py version sent to CPP in tracking request
TRACKING_CLIENT_VERSION = "4.1.0"

# Name of tracking client sent to CPP in tracking request
TRACKING_CLIENT_NAME = "wla"

STATIC_EXTENSIONS = set(
    ("gif jpg jpeg png bmp ico svg svgz ttf otf eot woff woff2 class swf css js xml webp").split()
)

STATIC_FILES = set(("robots.txt").split())

DOWNLOAD_EXTENSIONS = set(
    (
        "7z aac arc arj asf asx avi bin csv deb dmg doc docx exe flac flv gz gzip hqx "
        "ibooks jar json mpg mp2 mp3 mp4 mpeg mov movie msi msp odb odf odg odp "
        "ods odt ogg ogv pdf phps ppt pptx qt qtm ra ram rar rpm rtf sea sit tar tbz "
        "bz2 tbz tgz torrent txt wav webm wma wmv wpd xls xlsx xml xsd z zip "
        "azw3 epub mobi apk"
    ).split()
)

# A good source is: http://phpbb-bots.blogspot.com/
# user agents must be lowercase
EXCLUDED_USER_AGENTS = (
    "adsbot-google",
    "ask jeeves",
    "baidubot",
    "bot-",
    "bot/",
    "ccooter/",
    "crawl",
    "curl",
    "echoping",
    "exabot",
    "feed",
    "googlebot",
    "ia_archiver",
    "java/",
    "libwww",
    "mediapartners-google",
    "msnbot",
    "netcraftsurvey",
    "panopta",
    "pingdom.com_bot_",
    "robot",
    "spider",
    "surveybot",
    "twiceler",
    "voilabot",
    "yahoo",
    "yandex",
    "zabbix",
    "googlestackdrivermonitoring",
)

PIWIK_DEFAULT_MAX_ATTEMPTS = 3
PIWIK_DEFAULT_DELAY_AFTER_FAILURE = 10
DEFAULT_SOCKET_TIMEOUT = 300

PIWIK_EXPECTED_IMAGE = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAAAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="
)

#  Formats


def _get_site_id_and_url(site):
    return site["data"]["id"], site["data"]["attributes"]["urls"][0]


class BaseFormatException(Exception):
    pass


class BaseFormat:
    def __init__(self, name):
        self.name = name
        self.regex = None
        self.date_format = "%d/%b/%Y:%H:%M:%S"

    def check_format(self, file):
        line = file.readline()
        try:
            file.seek(0)
        except IOError:
            pass

        return self.check_format_line(line)

    def check_format_line(self, line):
        return False


class JsonFormat(BaseFormat):
    def __init__(self, name):
        super(JsonFormat, self).__init__(name)
        self.json = None
        self.date_format = "%Y-%m-%dT%H:%M:%S"

    def check_format_line(self, line):
        try:
            self.json = json.loads(line)
            return True
        except Exception:
            return False

    def match(self, line):
        try:
            # nginx outputs malformed JSON w/ hex escapes when confronted w/ non-UTF input.
            # We have to workaround this by converting hex escapes in strings to unicode escapes.
            # The conversion is naive, so it does not take into account the string's actual
            # encoding (which we don't have access to).
            line = line.replace("\\x", "\\u00")

            self.json = json.loads(line)
            return self
        except Exception:
            self.json = None
            return None

    def get(self, key):
        # Some ugly patchs ...
        if key == "generation_time_milli":
            self.json[key] = int(float(self.json[key]) * 1000)
        # Patch date format ISO 8601
        elif key == "date":
            tz = self.json[key][19:]
            self.json["timezone"] = tz.replace(":", "")
            self.json[key] = self.json[key][:19]

        try:
            return self.json[key]
        except KeyError:
            raise BaseFormatException()

    def get_all(
        self,
    ):
        return self.json

    def remove_ignored_groups(self, groups):
        for group in groups:
            del self.json[group]


class RegexFormat(BaseFormat):
    def __init__(self, name, regex, date_format=None):
        super(RegexFormat, self).__init__(name)
        if regex is not None:
            self.regex = re.compile(regex)
        if date_format is not None:
            self.date_format = date_format
        self.matched = None

    def check_format_line(self, line):
        return self.match(line)

    def match(self, line):
        if not self.regex:
            return None
        match_result = self.regex.match(line)
        if match_result:
            self.matched = match_result.groupdict()
            if "time" in self.matched:
                self.matched["date"] = self.matched["date"] + " " + self.matched["time"]
                del self.matched["time"]
        else:
            self.matched = None
        return match_result

    def get(self, key):
        try:
            return self.matched[key]
        except KeyError:
            raise BaseFormatException("Cannot find group '%s'." % key)

    def get_all(
        self,
    ):
        return self.matched

    def remove_ignored_groups(self, groups):
        for group in groups:
            del self.matched[group]


class W3cExtendedFormat(RegexFormat):
    FIELDS_LINE_PREFIX = "#Fields: "
    REGEX_UNKNOWN_FIELD = r'(?:".*?"|\S+)'

    fields = {
        "date": r'"?(?P<date>\d+[-\d+]+)"?',
        "time": r'"?(?P<time>[\d+:]+)[.\d]*?"?',
        "cs-uri-stem": r"(?P<path>/\S*)",
        "cs-uri-query": r"(?P<query_string>\S*)",
        "c-ip": r'"?(?P<ip>[\w*.:-]*)"?',
        "cs(User-Agent)": r'(?P<user_agent>".*?"|\S*)',
        "cs(Referer)": r"(?P<referrer>\S+)",
        "sc-status": r"(?P<status>\d+)",
        "sc-bytes": r"(?P<length>\S+)",
        "cs-host": r"(?P<host>\S+)",
        "cs-method": r"(?P<method>\S+)",
        "cs-username": r"(?P<userid>\S+)",
        "time-taken": r"(?P<generation_time_secs>[.\d]+)",
    }

    def __init__(self):
        super(W3cExtendedFormat, self).__init__("w3c_extended", None, "%Y-%m-%d %H:%M:%S")

    def check_format(self, file):
        try:
            file.seek(0)
        except IOError:
            pass

        self.create_regex(file)

        # if we couldn't create a regex, this file does not follow the W3C extended log file format
        if not self.regex:
            try:
                file.seek(0)
            except IOError:
                pass

            return

        first_line = file.readline()

        try:
            file.seek(0)
        except IOError:
            pass

        return self.check_format_line(first_line)

    def create_regex(self, file):
        fields_line = None
        if config.options.w3c_fields:
            fields_line = config.options.w3c_fields

        # collect all header lines up until the Fields: line
        # if we're reading from stdin, we can't seek, so don't read any more than the Fields line
        header_lines = []
        while fields_line is None:
            line = file.readline().strip()

            if not line:
                continue

            if not line.startswith("#"):
                break

            if line.startswith(self.FIELDS_LINE_PREFIX):
                fields_line = line
            else:
                header_lines.append(line)

        if not fields_line:
            return

        # store the header lines for a later check for IIS
        self.header_lines = header_lines

        # Parse the 'Fields: ' line to create the regex to use
        full_regex = []

        expected_fields = self._configure_expected_fields()

        # Skip the 'Fields: ' prefix.
        fields_line = fields_line[9:].strip()
        for field in re.split(r"\s+", fields_line):
            try:
                regex = expected_fields[field]
            except KeyError:
                regex = self.REGEX_UNKNOWN_FIELD
            full_regex.append(regex)
        full_regex = r"\s+".join(full_regex)

        logging.debug("Based on 'Fields:' line, computed regex to be %s", full_regex)

        self.regex = re.compile(full_regex)

    def _configure_expected_fields(self):
        expected_fields = type(
            self
        ).fields.copy()  # turn custom field mapping into field => regex mapping

        # if the --w3c-time-taken-millisecs option is used, make sure the time-taken field is
        # interpreted as milliseconds
        if config.options.w3c_time_taken_in_millisecs:
            expected_fields["time-taken"] = r"(?P<generation_time_milli>[\d.]+)"

        for mapped_field_name, field_name in config.options.custom_w3c_fields.items():
            expected_fields[mapped_field_name] = expected_fields[field_name]
            del expected_fields[field_name]

        # add custom field regexes supplied through --w3c-field-regex option
        for field_name, field_regex in config.options.w3c_field_regexes.items():
            expected_fields[field_name] = field_regex
        return expected_fields

    def check_for_iis_option(self):
        if (
            not config.options.w3c_time_taken_in_millisecs
            and self._is_time_taken_milli()
            and self._is_iis()
        ):
            logging.info(
                "WARNING: IIS log file being parsed without --w3c-time-taken-milli option. IIS"
                " stores millisecond values in the time-taken field. If your logfile does this, the"
                " aforementioned option must be used in order to get accurate generation times."
            )

    def _is_iis(self):
        return (
            len(
                [
                    line
                    for line in self.header_lines
                    if "internet information services" in line.lower() or "iis" in line.lower()
                ]
            )
            > 0
        )

    def _is_time_taken_milli(self):
        return "generation_time_milli" not in self.regex.pattern


class IisFormat(W3cExtendedFormat):
    fields = W3cExtendedFormat.fields.copy()
    fields.update(
        {
            "time-taken": r"(?P<generation_time_milli>[.\d]+)",
            "sc-win32-status": (  # this group is useless for log importing, but capturing it
                r"(?P<__win32_status>\S+)"
            )
            # will ensure we always select IIS for the format instead of
            # W3C logs when detecting the format. This way there will be
            # less accidental importing of IIS logs w/o --w3c-time-taken-milli.
        }
    )

    def __init__(self):
        super(IisFormat, self).__init__()

        self.name = "iis"


class IncapsulaW3CFormat(W3cExtendedFormat):
    # use custom unknown field regex to make resulting regex much simpler
    REGEX_UNKNOWN_FIELD = r'".*?"'

    fields = W3cExtendedFormat.fields.copy()
    # redefines all fields as they are always encapsulated with "
    fields.update(
        {
            "cs-uri": r'"(?P<host>[^\/\s]+)(?P<path>\S+)"',
            "cs-uri-query": r'"(?P<query_string>\S*)"',
            "c-ip": r'"(?P<ip>[\w*.:-]*)"',
            "cs(User-Agent)": r'"(?P<user_agent>.*?)"',
            "cs(Referer)": r'"(?P<referrer>\S+)"',
            "sc-status": r'(?P<status>"\d*")',
            "cs-bytes": r'(?P<length>"\d*")',
        }
    )

    def __init__(self):
        super(IncapsulaW3CFormat, self).__init__()

        self.name = "incapsula_w3c"

    def get(self, key):
        value = super(IncapsulaW3CFormat, self).get(key)
        if key == "status" or key == "length":
            value = value.strip('"')
        if key == "status" and value == "":
            value = "200"
        return value


class ShoutcastFormat(W3cExtendedFormat):
    fields = W3cExtendedFormat.fields.copy()
    fields.update(
        {
            "c-status": r"(?P<status>\d+)",
            "x-duration": r"(?P<generation_time_secs>[.\d]+)",
        }
    )

    def __init__(self):
        super(ShoutcastFormat, self).__init__()

        self.name = "shoutcast"

    def get(self, key):
        if key == "user_agent":
            user_agent = super(ShoutcastFormat, self).get(key)
            return urllib.parse.unquote(user_agent)
        else:
            return super(ShoutcastFormat, self).get(key)


class AmazonCloudFrontFormat(W3cExtendedFormat):
    fields = W3cExtendedFormat.fields.copy()
    fields.update(
        {
            "x-event": r"(?P<event_action>\S+)",
            "x-sname": r"(?P<event_name>\S+)",
            "cs-uri-stem": r"(?:rtmp:/)?(?P<path>/\S*)",
            "c-user-agent": r'(?P<user_agent>".*?"|\S+)',
            # following are present to match cloudfront instead of W3C when we know it's cloudfront
            "x-edge-location": r'(?P<x_edge_location>".*?"|\S+)',
            "x-edge-result-type": r'(?P<x_edge_result_type>".*?"|\S+)',
            "x-edge-request-id": r'(?P<x_edge_request_id>".*?"|\S+)',
            "x-host-header": r'(?P<host>".*?"|\S+)',
        }
    )

    def __init__(self):
        super(AmazonCloudFrontFormat, self).__init__()

        self.name = "amazon_cloudfront"

    def get(self, key):
        if key == "event_category" and "event_category" not in self.matched:
            return "cloudfront_rtmp"
        elif key == "status" and "status" not in self.matched:
            return "200"
        elif key == "user_agent":
            user_agent = super(AmazonCloudFrontFormat, self).get(key)
            return urllib.parse.unquote(urllib.parse.unquote(user_agent))  # Value is double quoted!
        else:
            return super(AmazonCloudFrontFormat, self).get(key)


_HOST_PREFIX = r"(?P<host>[\w\-\.]*)(?::\d+)?\s+"

_COMMON_LOG_FORMAT = (
    r"(?P<ip>[\w*.:-]+)\s+\S+\s+(?P<userid>\S+)\s+\[(?P<date>.*?)\s+(?P<timezone>.*?)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>.*?)\s+\S+"\s+(?P<status>\d+)\s+(?P<length>\S+)'
)
_NCSA_EXTENDED_LOG_FORMAT = _COMMON_LOG_FORMAT + r'\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)"'


_S3_LOG_FORMAT = (
    r"\S+\s+(?P<host>\S+)\s+\[(?P<date>.*?)\s+(?P<timezone>.*?)\]\s+(?P<ip>[\w*.:-]+)\s+"
    r'(?P<userid>\S+)\s+\S+\s+\S+\s+\S+\s+"(?P<method>\S+)\s+(?P<path>.*?)\s+\S+"\s+(?P<status>\d+)'
    r"\s+\S+\s+(?P<length>\S+)\s+"
    r'\S+\s+\S+\s+\S+\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)"'
)
_ICECAST2_LOG_FORMAT = _NCSA_EXTENDED_LOG_FORMAT + r"\s+(?P<session_time>[0-9-]+)"
_ELB_LOG_FORMAT = (
    r"(?:\S+\s+)?(?P<date>[0-9-]+T[0-9:]+)\.\S+\s+\S+\s+(?P<ip>[\w*.:-]+):\d+\s+\S+:\d+\s+\S+\s+"
    r"(?P<generation_time_secs>\S+)\s+\S+\s+"
    r"(?P<status>\d+)\s+\S+\s+\S+\s+(?P<length>\S+)\s+"
    r'"\S+\s+\w+:\/\/(?P<host>[\w\-\.]*):\d+(?P<path>\/\S*)\s+[^"]+"\s+"'
    r'(?P<user_agent>[^"]+)"\s+\S+\s+\S+'
)

_OVH_FORMAT = (
    r"(?P<ip>\S+)\s+" + _HOST_PREFIX + r"(?P<userid>\S+)\s+\[(?P<date>.*?)\s+(?P<timezone>.*?)\]\s+"
    r'"\S+\s+(?P<path>.*?)\s+\S+"\s+(?P<status>\S+)\s+(?P<length>\S+)'
    r'\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)"'
)

_HAPROXY_FORMAT = (
    r".*:\ (?P<ip>[\w*.]+).*\[(?P<date>.*)\].*\ (?P<status>\b\d{3}\b)\ "
    r"(?P<length>\d+)\ -.*\"(?P<method>\S+)\ (?P<path>\S+).*"
)

_GANDI_SIMPLE_HOSTING_FORMAT = (
    r"(?P<host>[0-9a-zA-Z-_.]+)\s+(?P<ip>[a-zA-Z0-9.]+)\s+\S+\s+(?P<userid>\S+)"
    r'\s+\[(?P<date>.+?)\s+(?P<timezone>.+?)\]\s+\((?P<generation_time_secs>[0-9a-zA-Z\s]*)\)\s+"'
    r'(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(\S+)"\s+(?P<status>[0-9]+)\s+(?P<length>\S+)\s+"'
    r'(?P<referrer>\S+)"\s+"(?P<user_agent>[^"]+)"'
)
FORMATS = {
    "common": RegexFormat("common", _COMMON_LOG_FORMAT),
    "common_vhost": RegexFormat("common_vhost", _HOST_PREFIX + _COMMON_LOG_FORMAT),
    "ncsa_extended": RegexFormat("ncsa_extended", _NCSA_EXTENDED_LOG_FORMAT),
    "common_complete": RegexFormat("common_complete", _HOST_PREFIX + _NCSA_EXTENDED_LOG_FORMAT),
    "w3c_extended": W3cExtendedFormat(),
    "amazon_cloudfront": AmazonCloudFrontFormat(),
    "incapsula_w3c": IncapsulaW3CFormat(),
    "iis": IisFormat(),
    "shoutcast": ShoutcastFormat(),
    "s3": RegexFormat("s3", _S3_LOG_FORMAT),
    "icecast2": RegexFormat("icecast2", _ICECAST2_LOG_FORMAT),
    "elb": RegexFormat("elb", _ELB_LOG_FORMAT, "%Y-%m-%dT%H:%M:%S"),
    "nginx_json": JsonFormat("nginx_json"),
    "ovh": RegexFormat("ovh", _OVH_FORMAT),
    "haproxy": RegexFormat("haproxy", _HAPROXY_FORMAT, "%d/%b/%Y:%H:%M:%S.%f"),
    "gandi": RegexFormat("gandi", _GANDI_SIMPLE_HOSTING_FORMAT, "%d/%b/%Y:%H:%M:%S"),
}


# Code


class StoreDictKeyPair(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        my_dict = getattr(namespace, self.dest, None)
        if not my_dict:
            my_dict = {}
        for kv in values.split(","):
            k, v = kv.split("=")
            my_dict[k] = v
        setattr(namespace, self.dest, my_dict)


class AddSlashAtStart(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed at AddSlashAtStart action")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if not isinstance(values, str):
            raise ValueError("--tracker-endpoint-path must be a string")
        setattr(namespace, self.dest, "/" + values if not values.startswith("/") else values)


class Configuration:
    """
    Stores all the configuration options by reading sys.argv and parsing.

    It has 2 attributes: options and filenames.
    """

    class Error(Exception):
        pass

    piwik_token = None

    def _create_parser(self):
        """
        Initialize and return the OptionParser instance.
        """
        parser = argparse.ArgumentParser(
            # usage='Usage: %prog [options] log_file [ log_file [...] ]',
            description=(
                "Import HTTP access logs to Piwik PRO. log_file is the path to a server access  log"
                " file (uncompressed, .gz, .bz2, or specify - to read from stdin). You may also"
                " import many log files at once (for example set log_file to *.log or *.log.gz). By"
                " default, the script will try to produce clean reports and will exclude bots,"
                " static files, discard http error and redirects, etc. This is customizable, see"
                " below."
            ),
            epilog=(
                "About Piwik PRO Server Log Analytics: https://github.com/PiwikPRO/log-analytics/ "
                " Found a bug? Please create a Github issue. "
            ),
        )

        parser.add_argument("file", type=str, nargs="+")

        # Basic auth user
        parser.add_argument(
            "--auth-user",
            dest="auth_user",
            help="Basic auth user",
        )
        # Basic auth password
        parser.add_argument(
            "--auth-password",
            dest="auth_password",
            help="Basic auth password",
        )
        parser.add_argument(
            "--debug",
            "-d",
            dest="debug",
            action="count",
            default=0,
            help="Enable debug output (specify multiple times for more verbose)",
        )
        parser.add_argument(
            "--debug-tracker",
            dest="debug_tracker",
            action="store_true",
            default=False,
            # This is now internal flag, not meant to be used by the users
            help=argparse.SUPPRESS,
        )
        parser.add_argument(
            "--debug-request-limit",
            dest="debug_request_limit",
            type=int,
            default=None,
            help=(
                "Debug option that will exit after N requests are parsed. Can be used w/"
                " --debug-tracker to limit the output of a large log file."
            ),
        )
        parser.add_argument(
            "--sleep-between-requests-ms",
            dest="sleep_between_requests_ms",
            default=False,
            type=float,
            help="Option that will force each recorder to sleep X milliseconds between "
            "tracker requests",
        )
        parser.add_argument(
            "--url",
            dest="piwik_url",
            required=True,
            help="REQUIRED Your Piwik PRO server URL, eg. https://example.piwik.pro/",
        )
        parser.add_argument(
            "--api-url",
            dest="piwik_api_url",
            help=(
                "This URL will be used to send API requests (use it if your tracker URL differs"
                " from UI/API url), eg. https://example.piwik.pro/"
            ),
        )
        parser.add_argument(
            "--tracker-endpoint-path",
            dest="piwik_tracker_endpoint_path",
            default="/ppms.php",
            action=AddSlashAtStart,
            help=(
                "The tracker endpoint path to use to send requests to tracker. Defaults to"
                " /ppms.php.If you want to change tracker endpoint that should be detected in logs"
                " files use `--replay-tracking-expected-tracker-file`."
            ),
        )
        parser.add_argument(
            "--dry-run",
            dest="dry_run",
            action="store_true",
            default=False,
            help="Perform a trial run with no tracking data being inserted into Piwik PRO",
        )
        parser.add_argument(
            "--show-progress",
            dest="show_progress",
            action="store_true",
            default=hasattr(sys.stdout, "fileno") and os.isatty(sys.stdout.fileno()),
            help=(
                "Print a progress report X seconds (default: 1, use --show-progress-delay to"
                " override)"
            ),
        )
        parser.add_argument(
            "--show-progress-delay",
            dest="show_progress_delay",
            type=int,
            default=1,
            help="Change the default progress delay",
        )
        parser.add_argument(
            "--idsite",
            dest="site_id",
            help=(
                "When specified, data in the specified log files will be tracked for this Piwik PRO"
                " App ID. The script will not auto-detect the website based on the log line"
                " hostname (new websites will not be automatically created)."
            ),
        )
        parser.add_argument(
            "--client-id",
            dest="client_id",
            help="Client ID used when OAuth authentication is needed",
        )
        parser.add_argument(
            "--client-secret",
            dest="client_secret",
            help="Client secret used when OAuth authentication is needed",
        )

        parser.add_argument(
            "--hostname",
            dest="hostnames",
            action="append",
            default=[],
            help=(
                "Accepted hostname (requests with other hostnames will be excluded). "
                " You may use the star character * "
                " Example: --hostname=*domain.com"
                " Can be specified multiple times"
            ),
        )
        parser.add_argument(
            "--exclude-path",
            dest="excluded_paths",
            action="append",
            default=[],
            help=(
                "Any URL path matching this exclude-path will not be imported in Piwik PRO. "
                " You must use the star character *. "
                " Example: --exclude-path=*/admin/*"
                " Can be specified multiple times. "
            ),
        )
        parser.add_argument(
            "--exclude-path-from",
            dest="exclude_path_from",
            help=(
                "Each line from this file is a path to exclude. Each path must contain the"
                " character * to match a string. (see: --exclude-path)"
            ),
        )
        parser.add_argument(
            "--include-path",
            dest="included_paths",
            action="append",
            default=[],
            help=(
                "Paths to include. Can be specified multiple times. If not specified, all paths are"
                " included."
            ),
        )
        parser.add_argument(
            "--include-path-from",
            dest="include_path_from",
            help="Each line from this file is a path to include",
        )
        parser.add_argument(
            "--useragent-exclude",
            dest="excluded_useragents",
            action="append",
            default=[],
            help=(
                "User agents to exclude (in addition to the standard excluded "
                "user agents). Can be specified multiple times"
            ),
        )
        parser.add_argument(
            "--enable-static",
            dest="enable_static",
            action="store_true",
            default=False,
            help="Track static files (images, css, js, ico, ttf, etc.)",
        )
        parser.add_argument(
            "--enable-bots",
            dest="enable_bots",
            action="store_true",
            default=False,
            help=(
                "Track bots. All bot visits will have a Custom Variable set with name='Bot' and"
                " value='$Bot_user_agent_here$'"
            ),
        )
        parser.add_argument(
            "--enable-http-errors",
            dest="enable_http_errors",
            action="store_true",
            default=False,
            help="Track HTTP errors (status code 4xx or 5xx)",
        )
        parser.add_argument(
            "--enable-http-redirects",
            dest="enable_http_redirects",
            action="store_true",
            default=False,
            help="Track HTTP redirects (status code 3xx except 304)",
        )
        parser.add_argument(
            "--enable-reverse-dns",
            dest="reverse_dns",
            action="store_true",
            default=False,
            help=(
                "Enable reverse DNS, used to generate the 'ISP' report in Piwik PRO. "
                "Disabled by default, as it impacts performance"
            ),
        )
        parser.add_argument(
            "--strip-query-string",
            dest="strip_query_string",
            action="store_true",
            default=False,
            help="Strip the query string from the URL",
        )
        parser.add_argument(
            "--query-string-delimiter",
            dest="query_string_delimiter",
            default="?",
            help="The query string delimiter (default: %(default)s)",
        )
        parser.add_argument(
            "--log-format-name",
            dest="log_format_name",
            default=None,
            help=(
                "Access log format to detect (supported are: %s). When not specified, the log"
                " format will be autodetected by trying all supported log formats."
                % ", ".join(sorted(FORMATS.keys()))
            ),
        )
        available_regex_groups = [
            "date",
            "path",
            "query_string",
            "ip",
            "user_agent",
            "referrer",
            "status",
            "length",
            "host",
            "userid",
            "generation_time_milli",
            "event_action",
            "event_name",
            "timezone",
            "session_time",
        ]
        parser.add_argument(
            "--log-format-regex",
            dest="log_format_regex",
            default=None,
            help=(
                "Regular expression used to parse log entries. Regexes must contain named groups"
                " for different log fields. Recognized fields include: %s. For an example of a"
                " supported Regex, see the source code of this file. Overrides --log-format-name."
            )
            % ", ".join(available_regex_groups),
        )
        parser.add_argument(
            "--log-date-format",
            dest="log_date_format",
            default=None,
            help=(
                "Format string used to parse dates. You can specify any format that can also be"
                " specified to the strptime python function."
            ),
        )
        parser.add_argument(
            "--log-hostname",
            dest="log_hostname",
            default=None,
            help=(
                "Force this hostname for a log format that doesn't include it. All hits "
                "will seem to come to this host"
            ),
        )
        parser.add_argument(
            "--skip",
            dest="skip",
            default=0,
            type=int,
            help=(
                "Skip the n first lines to start parsing/importing data at a given line for the"
                " specified log file"
            ),
        )
        parser.add_argument(
            "--recorders",
            dest="recorders",
            default=1,
            type=int,
            help=(
                "Number of simultaneous recorders (default: %(default)s). It should be set to the"
                " number of CPU cores in your server. You can also experiment with higher values"
                " which may increase performance until a certain point"
            ),
        )
        parser.add_argument(
            "--recorder-max-payload-size",
            dest="recorder_max_payload_size",
            default=95,
            type=int,
            help=(
                "Maximum number of log entries to record in one tracking request (default:"
                " %(default)s). "
            ),
        )
        parser.add_argument(
            "--replay-tracking",
            dest="replay_tracking",
            action="store_true",
            default=False,
            help=(
                "Replay requests to the Tracker found in custom logs (only piwik.php, ppms.php, js/"
                " or js/tracker.php requests expected, but it can be configured with"
                " --replay-tracking-expected-tracker-file option)."
            ),
        )
        parser.add_argument(
            "--replay-tracking-expected-tracker-file",
            dest="replay_tracking_expected_tracker_file",
            default=None,
            help=(
                "The expected suffix for tracking request paths. Only logs whose paths end with"
                " this will be imported. Defaults to 'piwik.php', 'ppms.php', 'js/' or"
                " 'js/tracker.php' so only requests to those files will be imported."
            ),
        )
        parser.add_argument(
            "--output",
            dest="output",
            help="Redirect output (stdout and stderr) to the specified file",
        )
        parser.add_argument(
            "--encoding",
            dest="encoding",
            default="utf8",
            help="Log files encoding (default: %(default)s)",
        )
        parser.add_argument(
            "--disable-bulk-tracking",
            dest="disable_bulk_tracking",
            default=False,
            action="store_true",
            help=(
                "Disables use of bulk tracking so recorders record single with every request"
                " to the tracker."
            ),
        )
        parser.add_argument(
            "--force-lowercase-path",
            dest="force_lowercase_path",
            default=False,
            action="store_true",
            help=(
                "Make URL path lowercase so paths with the same letters but different cases are "
                "treated the same."
            ),
        )
        parser.add_argument(
            "--download-extensions",
            dest="download_extensions",
            default=None,
            help=(
                "By default Piwik PRO tracks as Downloads the most popular file extensions. If you"
                " set this parameter (format: pdf,doc,...) then files with an extension found in"
                " the list will be imported as Downloads, other file extensions downloads will be"
                " skipped."
            ),
        )
        parser.add_argument(
            "--add-download-extensions",
            dest="extra_download_extensions",
            default=None,
            help=(
                "Add extensions that should be treated as downloads. See --download-extensions for"
                " more info."
            ),
        )
        parser.add_argument(
            "--w3c-map-field",
            action=StoreDictKeyPair,
            metavar="KEY=VAL",
            default={},
            dest="custom_w3c_fields",
            help=(
                "Map a custom log entry field in your W3C log to a default one. Use this option to"
                " load custom log files that use the W3C extended log format such as those from the"
                " Advanced Logging W3C module. Used as, eg, --w3c-map-field my-date=date."
                " Recognized default fields include: %s\n\nFormats that extend the W3C extended log"
                " format (like the cloudfront RTMP log format) may define more fields that can be"
                " mapped."
            )
            % ", ".join(list(W3cExtendedFormat.fields.keys())),
        )
        parser.add_argument(
            "--w3c-time-taken-millisecs",
            action="store_true",
            default=False,
            dest="w3c_time_taken_in_millisecs",
            help=(
                "If set, interprets the time-taken W3C log field as a number of milliseconds. This"
                " must be set for importing IIS logs."
            ),
        )
        parser.add_argument(
            "--w3c-fields",
            dest="w3c_fields",
            default=None,
            help=(
                "Specify the '#Fields:' line for a log file in the W3C Extended log file format."
                " Use this option if your log file doesn't contain the '#Fields:' line which is"
                " required for parsing. This option must be used in conjunction with"
                " --log-format-name=w3c_extended.\nExample: --w3c-fields='#Fields: date time c-ip"
                " ...'"
            ),
        )
        parser.add_argument(
            "--w3c-field-regex",
            action=StoreDictKeyPair,
            metavar="KEY=VAL",
            default={},
            dest="w3c_field_regexes",
            type=str,
            help=(
                "Specify a regex for a field in your W3C extended log file. You can use this option"
                " to parse fields the importer does not natively recognize and then use one of the"
                " --regex-group-to-XXX-cvar options to track the field in a custom variable. For"
                " example, specifying --w3c-field-regex=sc-win32-status=(?P<win32_status>\\S+)"
                ' --regex-group-to-page-cvar="win32_status=Windows Status Code" will track the'
                " sc-win32-status IIS field in the 'Windows Status Code' custom variable. Regexes"
                " must contain a named group."
            ),
        )
        parser.add_argument(
            "--title-category-delimiter",
            dest="title_category_delimiter",
            default="/",
            help=(
                "If --enable-http-errors is used, errors are shown in the page titles report. If"
                " you have changed General.action_title_category_delimiter in your Piwik PRO"
                " configuration, you need to set this option to the same value in order to get a"
                " pretty page titles report."
            ),
        )
        parser.add_argument(
            "--dump-log-regex",
            dest="dump_log_regex",
            action="store_true",
            default=False,
            help=(
                "Prints out the regex string used to parse log lines and exists. Can be useful for"
                " using formats in newer versions of the script in older versions of the script."
                " The output regex can be used with the --log-format-regex option."
            ),
        )

        parser.add_argument(
            "--ignore-groups",
            dest="regex_groups_to_ignore",
            default=None,
            help=(
                "Comma separated list of regex groups to ignore when parsing log lines. Can be used"
                " to, for example, disable normal user id tracking. See documentation for"
                " --log-format-regex for list of available regex groups."
            ),
        )

        parser.add_argument(
            "--regex-group-to-visit-cvar",
            action=StoreDictKeyPair,
            metavar="KEY=VAL",
            dest="regex_group_to_visit_cvars_map",
            default={},
            help=(
                "Track an attribute through a custom variable with visit scope instead of through"
                " Piwik PRO's normal approach. For example, to track usernames as a custom variable"
                " instead of through the uid tracking parameter, supply"
                ' --regex-group-to-visit-cvar="userid=User Name". This will track usernames in a'
                " custom variable named 'User Name'. The list of available regex groups can be"
                " found in the documentation for --log-format-regex (additional regex groups you"
                " may have defined in --log-format-regex can also be used)."
            ),
        )
        parser.add_argument(
            "--regex-group-to-page-cvar",
            action=StoreDictKeyPair,
            metavar="KEY=VAL",
            dest="regex_group_to_page_cvars_map",
            default={},
            help=(
                "Track an attribute through a custom variable with page scope instead of through"
                " Piwik PRO's normal approach. For example, to track usernames as a custom variable"
                " instead of through the uid tracking parameter, supply"
                ' --regex-group-to-page-cvar="userid=User Name". This will track usernames in a'
                " custom variable named 'User Name'. The list of available regex groups can be"
                " found in the documentation for --log-format-regex (additional regex groups you"
                " may have defined in --log-format-regex can also be used)."
            ),
        )
        parser.add_argument(
            "--track-http-method",
            dest="track_http_method",
            default=False,
            help=(
                "Enables tracking of http method as custom page variable if method group is"
                " available in log format."
            ),
        )
        parser.add_argument(
            "--retry-max-attempts",
            dest="max_attempts",
            default=PIWIK_DEFAULT_MAX_ATTEMPTS,
            type=int,
            help="The maximum number of times to retry a failed tracking request.",
        )
        parser.add_argument(
            "--retry-delay",
            dest="delay_after_failure",
            default=PIWIK_DEFAULT_DELAY_AFTER_FAILURE,
            type=int,
            help="The number of seconds to wait before retrying a failed tracking request.",
        )
        parser.add_argument(
            "--request-timeout",
            dest="request_timeout",
            default=DEFAULT_SOCKET_TIMEOUT,
            type=int,
            help=(
                "The maximum number of seconds to wait before terminating an HTTP request to Piwik"
                " PRO."
            ),
        )
        parser.add_argument(
            "--include-host",
            action="append",
            type=str,
            help="Only import logs from the specified host(s).",
        )
        parser.add_argument(
            "--exclude-host",
            action="append",
            type=str,
            help="Only import logs that are not from the specified host(s).",
        )
        parser.add_argument(
            "--exclude-older-than",
            type=self._valid_date,
            default=None,
            help=(
                "Ignore logs older than the specified date. Exclusive. Date format must be"
                " YYYY-MM-DD hh:mm:ss +/-0000. The timezone offset is required."
            ),
        )
        parser.add_argument(
            "--exclude-newer-than",
            type=self._valid_date,
            default=None,
            help=(
                "Ignore logs newer than the specified date. Exclusive. Date format must be"
                " YYYY-MM-DD hh:mm:ss +/-0000. The timezone offset is required."
            ),
        )
        parser.add_argument(
            "--add-to-date",
            dest="seconds_to_add_to_date",
            default=0,
            type=int,
            help="A number of seconds to add to each date value in the log file.",
        )
        parser.add_argument(
            "--request-suffix",
            dest="request_suffix",
            default=None,
            type=str,
            help="Extra parameters to append to tracker and API requests.",
        )
        parser.add_argument(
            "--accept-invalid-ssl-certificate",
            dest="accept_invalid_ssl_certificate",
            action="store_true",
            default=False,
            help="Do not verify the SSL / TLS certificate when contacting the Piwik PRO server.",
        )
        return parser

    def _valid_date(self, value):
        try:
            (date_str, timezone) = value.rsplit(" ", 1)
        except Exception:
            raise argparse.ArgumentTypeError("Invalid date value '%s'." % value)

        if not re.match("[-+][0-9]{4}", timezone):
            raise argparse.ArgumentTypeError(
                "Invalid date value '%s': expected valid timzeone like +0100 or -1200, got '%s'"
                % (value, timezone)
            )

        date = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        date -= TimeHelper.timedelta_from_timezone(timezone)

        return date

    def _parse_args(self, option_parser, argv=None):
        """
        Parse the command line args and create self.options and self.filenames.
        """
        if not argv:
            argv = sys.argv[1:]

        self.options = option_parser.parse_args(argv)
        self.filenames = self.options.file

        if self.options.output:
            sys.stdout = sys.stderr = open(self.options.output, "a")

        self._parse_filenames_options()

        # Configure logging before calling logging.{debug,info}.
        logging.basicConfig(
            format="%(asctime)s: [%(levelname)s] %(message)s",
            level=logging.DEBUG if self.options.debug >= 1 else logging.INFO,
        )

        self.options.excluded_useragents = set(
            [s.lower() for s in self.options.excluded_useragents]
        )

        self._parse_paths()

        if self.options.hostnames:
            logging.debug("Accepted hostnames: %s", ", ".join(self.options.hostnames))
        else:
            logging.debug("Accepted hostnames: all")

        self._parse_log_format_options()

        self._parse_w3c_options()

        if not (
            self.options.piwik_url.startswith("http://")
            or self.options.piwik_url.startswith("https://")
        ):
            self.options.piwik_url = "https://" + self.options.piwik_url
        logging.debug("Piwik PRO Tracker API URL is: %s", self.options.piwik_url)

        if not self.options.piwik_api_url:
            self.options.piwik_api_url = self.options.piwik_url

        if not (
            self.options.piwik_api_url.startswith("http://")
            or self.options.piwik_api_url.startswith("https://")
        ):
            self.options.piwik_api_url = "https://" + self.options.piwik_api_url
        logging.debug("Piwik PRO Analytics API URL is: %s", self.options.piwik_api_url)

        if self.options.recorders < 1:
            self.options.recorders = 1

        self._parse_extension_args()

        if self.options.regex_groups_to_ignore:
            self.options.regex_groups_to_ignore = set(
                self.options.regex_groups_to_ignore.split(",")
            )

    def _parse_filenames_options(self):
        all_filenames = []
        for self.filename in self.filenames:
            if self.filename == "-":
                all_filenames.append(self.filename)
            else:
                all_filenames = all_filenames + sorted(glob.glob(self.filename))
        self.filenames = all_filenames

    def _parse_extension_args(self):
        download_extensions = DOWNLOAD_EXTENSIONS
        if self.options.download_extensions:
            download_extensions = set(self.options.download_extensions.split(","))

        if self.options.extra_download_extensions:
            download_extensions.update(self.options.extra_download_extensions.split(","))
        self.options.download_extensions = download_extensions

    def _parse_paths(self):
        if self.options.exclude_path_from:
            paths = [path.strip() for path in open(self.options.exclude_path_from).readlines()]
            self.options.excluded_paths.extend(path for path in paths if len(path) > 0)
        if self.options.excluded_paths:
            self.options.excluded_paths = set(self.options.excluded_paths)
            logging.debug("Excluded paths: %s", " ".join(self.options.excluded_paths))

        if self.options.include_path_from:
            paths = [path.strip() for path in open(self.options.include_path_from).readlines()]
            self.options.included_paths.extend(path for path in paths if len(path) > 0)
        if self.options.included_paths:
            self.options.included_paths = set(self.options.included_paths)
            logging.debug("Included paths: %s", " ".join(self.options.included_paths))

    def _parse_log_format_options(self):
        if self.options.log_format_regex:
            self.format = RegexFormat(
                "custom", self.options.log_format_regex, self.options.log_date_format
            )
        elif self.options.log_format_name:
            try:
                self.format = FORMATS[self.options.log_format_name]
            except KeyError:
                fatal_error("invalid log format: %s" % self.options.log_format_name)
        else:
            self.format = None

    def _parse_w3c_options(self):
        if not hasattr(self.options, "custom_w3c_fields"):
            self.options.custom_w3c_fields = {}
        elif self.format is not None:
            # validate custom field mappings
            for (
                dummy_custom_name,
                default_name,
            ) in self.options.custom_w3c_fields.items():
                if default_name not in type(format).fields:
                    fatal_error(
                        "custom W3C field mapping error: don't know how to parse and use the '%s'"
                        " field" % default_name
                    )
                    return

        if hasattr(self.options, "w3c_field_regexes"):
            # make sure each custom w3c field regex has a named group
            for field_name, field_regex in self.options.w3c_field_regexes.items():
                if "(?P<" not in field_regex:
                    fatal_error(
                        "cannot find named group in custom w3c field regex '%s' for field '%s'"
                        % (field_regex, field_name)
                    )
                    return

    def __init__(self, argv=None):
        self._parse_args(self._create_parser(), argv)

    def _get_token_auth(self):
        """
        Get OAuth token based on client ID and secret
        """

        if self.options.client_id and self.options.client_secret:
            client_id = self.options.client_id
            client_secret = self.options.client_secret

            logging.debug("Using credentials: (client_id = %s)", client_id)
            try:
                api_result = piwik._call_api(
                    "/auth/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": client_secret,
                    },
                )
            except urllib.error.URLError as e:
                fatal_error("error when fetching OAuth token from the API: %s" % e)

            return api_result
        else:
            fatal_error(
                "OAuth authentication failed. Make sure that --client-id and --client-secret"
                " options are provided."
            )

    def get_resolver(self):
        if self.options.site_id:
            logging.debug("Resolver: static")
            return StaticResolver(self.options.site_id)
        else:
            logging.debug("Resolver: dynamic")
            return DynamicResolver()

    def init_token_auth(self):
        self.piwik_token = None
        if not config.options.replay_tracking:
            self.piwik_token = self._get_token_auth()
        logging.debug("Authentication token is: %s", self.piwik_token)


class Statistics:
    """
    Store statistics about parsed logs and recorded entries.
    Can optionally print statistics on standard output every second.
    """

    class Counter:
        """
        Simple integers cannot be used by multithreaded programs. See:
        https://stackoverflow.com/questions/6320107/are-python-ints-thread-safe
        """

        def __init__(self):
            # itertools.count's implementation in C does not release the GIL and
            # therefore is thread-safe.
            self.counter = itertools.count(1)
            self.value = 0

        def increment(self):
            self.value = next(self.counter)

        def advance(self, n):
            for i in range(n):
                self.increment()

        def __str__(self):
            return str(int(self.value))

    def __init__(self):
        self.time_start = None
        self.time_stop = None

        self.piwik_sites = set()  # sites ID
        self.piwik_sites_ignored = set()  # hostname

        self.count_lines_parsed = self.Counter()
        self.count_lines_recorded = self.Counter()

        # requests that the Piwik PRO Tracker considered invalid (or failed to track)
        self.invalid_lines = []

        # Do not match the regexp.
        self.count_lines_invalid = self.Counter()
        # Were filtered out.
        self.count_lines_filtered = self.Counter()
        # No app ID found by the resolver.
        self.count_lines_no_site = self.Counter()
        # Hostname filtered by config.options.hostnames
        self.count_lines_hostname_skipped = self.Counter()
        # Static files.
        self.count_lines_static = self.Counter()
        # Ignored user-agents.
        self.count_lines_skipped_user_agent = self.Counter()
        # Ignored HTTP errors.
        self.count_lines_skipped_http_errors = self.Counter()
        # Ignored HTTP redirects.
        self.count_lines_skipped_http_redirects = self.Counter()
        # Downloads
        self.count_lines_downloads = self.Counter()
        # Ignored downloads when --download-extensions is used
        self.count_lines_skipped_downloads = self.Counter()

        # Misc
        self.dates_recorded = set()
        self.monitor_stop = False

    def set_time_start(self):
        self.time_start = time.time()

    def set_time_stop(self):
        self.time_stop = time.time()

    def _compute_speed(self, value, start, end):
        delta_time = end - start
        if value == 0:
            return 0
        if delta_time == 0:
            return "very high!"
        else:
            return value / delta_time

    def _round_value(self, value, base=100):
        return round(value * base) / base

    def _indent_text(self, lines, level=1):
        """
        Return an indented text. 'lines' can be a list of lines or a single
        line (as a string). One level of indentation is 4 spaces.
        """
        prefix = " " * (4 * level)
        if isinstance(lines, str):
            return prefix + lines
        else:
            return "\n".join(prefix + line for line in lines)

    def print_summary(self):
        self.invalid_lines_summary = ""
        if self.invalid_lines:
            self.invalid_lines_summary = """Invalid log lines
-----------------

The following lines were not tracked by Piwik PRO, either due to a malformed tracker request
or error in the tracker:

%s

""" % textwrap.fill(
                ", ".join(self.invalid_lines), 80
            )
        print(
            (
                """
%(invalid_lines)sLogs import summary
-------------------

    %(count_lines_recorded)d requests imported successfully
    %(count_lines_downloads)d requests were downloads
    %(total_lines_ignored)d requests ignored:
        %(count_lines_skipped_http_errors)d HTTP errors
        %(count_lines_skipped_http_redirects)d HTTP redirects
        %(count_lines_invalid)d invalid log lines
        %(count_lines_filtered)d filtered log lines
        %(count_lines_no_site)d requests did not match any known site
        %(count_lines_hostname_skipped)d requests did not match any --hostname
        %(count_lines_skipped_user_agent)d requests done by bots, search engines...
        %(count_lines_static)d requests to static resources (css, js, images, ico, ttf...)
        %(count_lines_skipped_downloads)d requests to file downloads did not match any extension

Website import summary
----------------------

    %(count_lines_recorded)d requests imported to %(total_sites)d sites
    %(total_sites_ignored)d distinct hostnames did not match any existing site:
%(sites_ignored)s
%(sites_ignored_tips)s

Performance summary
-------------------

    Total time: %(total_time)d seconds
    Requests imported per second: %(speed_recording)s requests per second
"""
                % {
                    "count_lines_recorded": self.count_lines_recorded.value,
                    "count_lines_downloads": self.count_lines_downloads.value,
                    "total_lines_ignored": sum(
                        [
                            self.count_lines_invalid.value,
                            self.count_lines_filtered.value,
                            self.count_lines_skipped_user_agent.value,
                            self.count_lines_skipped_http_errors.value,
                            self.count_lines_skipped_http_redirects.value,
                            self.count_lines_static.value,
                            self.count_lines_skipped_downloads.value,
                            self.count_lines_no_site.value,
                            self.count_lines_hostname_skipped.value,
                        ]
                    ),
                    "count_lines_invalid": self.count_lines_invalid.value,
                    "count_lines_filtered": self.count_lines_filtered.value,
                    "count_lines_skipped_user_agent": self.count_lines_skipped_user_agent.value,
                    "count_lines_skipped_http_errors": self.count_lines_skipped_http_errors.value,
                    "count_lines_skipped_http_redirects": self.count_lines_skipped_http_redirects.value,  # noqa: E501
                    "count_lines_static": self.count_lines_static.value,
                    "count_lines_skipped_downloads": self.count_lines_skipped_downloads.value,
                    "count_lines_no_site": self.count_lines_no_site.value,
                    "count_lines_hostname_skipped": self.count_lines_hostname_skipped.value,
                    "total_sites": len(self.piwik_sites),
                    "total_sites_ignored": len(self.piwik_sites_ignored),
                    "sites_ignored": self._indent_text(
                        self.piwik_sites_ignored,
                        level=3,
                    ),
                    "sites_ignored_tips": """
        TIPs:
         - use --idsite to force all lines in the specified log files
           to be all recorded in the specified idsite
         - or you can also manually create a new Website in Piwik PRO with the URL set to this hostname
"""  # noqa: E501
                    if self.piwik_sites_ignored
                    else "",
                    "total_time": self.time_stop - self.time_start,
                    "speed_recording": self._round_value(
                        self._compute_speed(
                            self.count_lines_recorded.value,
                            self.time_start,
                            self.time_stop,
                        )
                    ),
                    "invalid_lines": self.invalid_lines_summary,
                }
            )
        )

    # The monitor is a thread that prints a short summary each second

    def _monitor(self):
        latest_total_recorded = 0
        while not self.monitor_stop:
            current_total = stats.count_lines_recorded.value
            time_elapsed = time.time() - self.time_start
            print(
                "%d lines parsed, %d lines recorded, %d records/sec (avg), %d records/sec (current)"
                % (
                    stats.count_lines_parsed.value,
                    current_total,
                    current_total / time_elapsed if time_elapsed != 0 else 0,
                    (current_total - latest_total_recorded) / config.options.show_progress_delay,
                )
            )
            latest_total_recorded = current_total
            time.sleep(config.options.show_progress_delay)

    def start_monitor(self):
        t = threading.Thread(target=self._monitor)
        t.daemon = True
        t.start()

    def stop_monitor(self):
        self.monitor_stop = True


class TimeHelper:
    @staticmethod
    def timedelta_from_timezone(timezone):
        timezone = int(timezone)
        sign = 1 if timezone >= 0 else -1
        n = abs(timezone)

        hours = int(n / 100) * sign
        minutes = n % 100 * sign

        return datetime.timedelta(hours=hours, minutes=minutes)


class UrlHelper:
    @staticmethod
    def convert_array_args(args):
        """
        Converts PHP deep query param arrays (eg, w/ names like hsr_ev[abc][0][]=value)
        into a nested list/dict structure that will convert correctly to JSON.
        """

        final_args = collections.OrderedDict()
        for key, value in args.items():
            indices = key.split("[")
            if "[" in key:
                # contains list of all indices, eg for abc[def][ghi][] = 123,
                # indices would be ['abc', 'def', 'ghi', '']
                indices = [i.rstrip("]") for i in indices]

                # navigate the multidimensional array final_args,
                # creating lists/dicts when needed, using indices
                element = final_args
                for i in range(0, len(indices) - 1):
                    idx = indices[i]

                    # if there's no next key, then this element is a list, otherwise a dict
                    element_type = list if not indices[i + 1] else dict
                    if idx not in element or not isinstance(element[idx], element_type):
                        element[idx] = element_type()

                    element = element[idx]

                # set the value in the final container we navigated to
                if not indices[-1]:  # last indice is '[]'
                    element.append(value)
                else:  # last indice has a key, eg, '[abc]'
                    element[indices[-1]] = value
            else:
                final_args[key] = value

        return UrlHelper._convert_dicts_to_arrays(final_args)

    @staticmethod
    def _convert_dicts_to_arrays(d):
        # convert dicts that have contiguous integer keys to arrays
        for key, value in d.items():
            if not isinstance(value, dict):
                continue

            if UrlHelper._has_contiguous_int_keys(value):
                d[key] = UrlHelper._convert_dict_to_array(value)
            else:
                d[key] = UrlHelper._convert_dicts_to_arrays(value)

        return d

    @staticmethod
    def _has_contiguous_int_keys(d):
        for i in range(0, len(d)):
            if str(i) not in d:
                return False
        return True

    @staticmethod
    def _convert_dict_to_array(d):
        result = []
        for i in range(0, len(d)):
            result.append(d[str(i)])
        return result


class PiwikHttpBase:
    class Error(Exception):
        def __init__(self, message, code=None):
            super(PiwikHttpBase.Error, self).__init__(message)

            self.code = code


class PiwikHttpUrllib(PiwikHttpBase):
    """
    Make requests to Piwik PRO.
    """

    class RedirectHandlerWithLogging(urllib.request.HTTPRedirectHandler):
        """
        Special implementation of HTTPRedirectHandler that logs redirects in debug mode
        to help users debug system issues.
        """

        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            logging.debug("Request redirected (code: %s) to '%s'" % (code, newurl))

            return urllib.request.HTTPRedirectHandler.redirect_request(
                self, req, fp, code, msg, hdrs, newurl
            )

    def _call(self, path, args=None, headers=None, url=None, data=None):
        """
        Make a request to the Piwik PRO site. It is up to the caller to format
        arguments, to embed authentication, etc.
        """
        if url is None:
            url = config.options.piwik_url
        headers = headers or {}

        if data and not isinstance(data, str) and headers["Content-type"] == "application/json":
            data = json.dumps(data).encode("utf-8")

        if args:
            path = path + "?" + urllib.parse.urlencode(args)

        if config.options.request_suffix:
            path = path + ("&" if "?" in path else "?") + config.options.request_suffix

        headers["User-Agent"] = "PiwikPRO/LogImport"

        try:
            timeout = config.options.request_timeout
        except Exception:
            timeout = None  # the config global object may not be created at this point

        request = urllib.request.Request(url + path, data, headers)
        logging.debug("Request url '%s'" % url)
        logging.debug("Request path '%s'" % path)
        logging.debug("Request method '%s'" % request.get_method())
        logging.debug("Request query args '%s'" % args)
        logging.debug("Request headers '%s'" % headers)
        logging.debug("Request data '%s'" % data)
        logging.debug("Request to '%s'" % request.get_full_url())

        self._handle_basic_auth(request)
        # Use non-default SSL context if invalid certificates shall be
        # accepted.
        if config.options.accept_invalid_ssl_certificate and sys.version_info >= (
            2,
            7,
            9,
        ):
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            https_handler_args = {"context": ssl_context}
        else:
            https_handler_args = {}
        opener = urllib.request.build_opener(
            self.RedirectHandlerWithLogging(),
            urllib.request.HTTPSHandler(**https_handler_args),
        )
        response = opener.open(request, timeout=timeout)
        encoding = response.info().get_content_charset("utf-8")
        result = response.read()
        response.close()
        # Replaces characters that can't be decoded with binary representation (e.g. '\\x80abc')
        result = result.decode(encoding, "backslashreplace")
        logging.debug("Response '%s'" % result)
        return result

    def _handle_basic_auth(self, request):
        # Handle basic auth if auth_user set
        try:
            auth_user = config.options.auth_user
            auth_password = config.options.auth_password
        except Exception:
            auth_user = None
            auth_password = None

        if auth_user is not None:
            base64string = (
                base64.encodebytes("{}:{}".format(auth_user, auth_password).encode())
                .decode()
                .replace("\n", "")
            )
            request.add_header("Authorization", "Basic %s" % base64string)

    def _call_api(self, path, args=None, data=None, headers=None):
        if headers is None:
            headers = {
                "Content-type": "application/json",
            }
        else:
            headers = dict(headers)

        if config.piwik_token:
            headers["Authorization"] = (
                config.piwik_token["token_type"] + " " + config.piwik_token["access_token"]
            )

        result = self._call(path, args=args, data=data, headers=headers)

        try:
            return json.loads(result)
        except ValueError:
            raise urllib.error.URLError(
                "Piwik PRO returned an invalid response: " + result.decode("utf-8")
            )

    def _call_wrapper(self, func, expected_response, on_failure, *args, **kwargs):
        """
        Try to make requests to Piwik PRO at most PIWIK_FAILURE_MAX_RETRY times.
        """
        errors = 0
        while True:
            try:
                response = func(*args, **kwargs)
                if expected_response is not None and response != expected_response:
                    if on_failure is not None:
                        error_message = on_failure(response, kwargs.get("data"))
                    else:
                        error_message = (
                            "didn't receive the expected response '%s'. Response was '%s' "
                            % expected_response,
                            response,
                        )

                    raise urllib.error.URLError(error_message)
                return response
            except (
                urllib.error.URLError,
                http.client.HTTPException,
                ValueError,
                socket.timeout,
            ) as e:
                logging.info("Error when connecting to Piwik: %s", e)

                code, message = self._parse_http_exception(e)

                try:
                    delay_after_failure = config.options.delay_after_failure
                    max_attempts = config.options.max_attempts
                except NameError:
                    delay_after_failure = PIWIK_DEFAULT_DELAY_AFTER_FAILURE
                    max_attempts = PIWIK_DEFAULT_MAX_ATTEMPTS

                errors += 1
                if errors == max_attempts:
                    logging.info("Max number of attempts reached, server is unreachable!")

                    raise PiwikHttpBase.Error(message, code)
                else:
                    logging.info("Retrying request, attempt number %d" % (errors + 1))

                    time.sleep(delay_after_failure)

    def _parse_http_exception(self, e):
        code = None
        if isinstance(e, urllib.error.HTTPError):
            # See Python issue 13211.
            message = "HTTP Error %s %s" % (e.code, e.msg)
            code = e.code
        elif isinstance(e, urllib.error.URLError):
            message = e.reason
        else:
            message = str(e)

        # decorate message w/ HTTP response, if it can be retrieved
        if hasattr(e, "read"):
            message = message + ", response: " + e.read().decode()
        return code, message

    def _call_authentication_wrapper(self, func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except urllib.error.URLError as e:
            if getattr(e, "code", None) == 401:
                config.init_token_auth()
                return func(*args, **kwargs)
            else:
                raise

    def auth_call(self, path, args, headers=None, data=None):
        return self._call_authentication_wrapper(self._call, path, args, headers, data=data)

    def auth_call_api(self, method, **kwargs):
        return self._call_authentication_wrapper(self._call_api, method, **kwargs)

    def call(
        self,
        path,
        args,
        expected_content=None,
        headers=None,
        data=None,
        on_failure=None,
    ):
        return self._call_wrapper(
            self.auth_call, expected_content, on_failure, path, args, headers, data=data
        )

    def call_api(self, method, **kwargs):
        return self._call_wrapper(self.auth_call_api, None, None, method, **kwargs)


# Resolvers
# A resolver is a class that turns a hostname into a Piwik PRO app ID.


class StaticResolver:
    """
    Always return the same app ID, specified in the configuration.
    """

    def __init__(self, site_id):
        self.initial_site_id = site_id
        self.site_id = site_id
        self._main_url = None
        if not config.options.replay_tracking:
            # Go get the main URL
            try:
                site = piwik.auth_call_api("/api/apps/v2/%s" % site_id)
            except urllib.error.URLError as e:
                if e.code == 404:
                    logging.debug("cannot get the main URL of this App ID: %s" % site_id)
                    self.site_id = None
            else:
                if site.get("result") == "error":
                    fatal_error("cannot get the main URL of this App: %s" % site.get("message"))

                try:
                    self.site_id, self._main_url = _get_site_id_and_url(site)
                except KeyError:
                    pass

        if self.site_id is not None:
            stats.piwik_sites.add(self.site_id)

    def resolve(self, hit):
        return (self.site_id, self._main_url)

    def check_format(self, format):
        pass


class DynamicResolver:
    """
    Use Piwik PRO API to determine the app ID.
    """

    def __init__(self):
        self._cache = {"sites": {}}

    def _get_site_id_from_hit_host(self, hit):
        try:
            return piwik.auth_call_api(
                "/api/tracker/v2/settings/app/url", args={"app_url": hit.host}
            )
        except urllib.error.URLError as e:
            if e.code == 404:
                return None
            raise

    def _resolve(self, hit):
        site_id = None
        res = self._get_site_id_from_hit_host(hit)
        if res:
            # The site already exists.
            site_id, _ = _get_site_id_and_url(res)
        if site_id is not None:
            stats.piwik_sites.add(site_id)
        return site_id

    def _resolve_when_replay_tracking(self, hit):
        """
        If parsed app ID found in the _cache['sites'] return app ID and main_url,
        otherwise return (None, None) tuple.
        """
        site_id = hit.args["idsite"]
        stats.piwik_sites.add(site_id)
        return site_id, None

    def _resolve_by_host(self, hit):
        """
        Returns the app ID and site URL for a hit based on the hostname.
        """
        try:
            site_id = self._cache[hit.host]
        except KeyError:
            logging.debug("App ID for hostname %s not in cache", hit.host)
            site_id = self._resolve(hit)
            logging.debug("App ID for hostname %s: %s", hit.host, site_id)
            self._cache[hit.host] = site_id
        return (site_id, "https://" + hit.host)

    def resolve(self, hit):
        """
        Return the app ID from the cache if found, otherwise call _resolve.
        If replay_tracking option is enabled, call _resolve_when_replay_tracking.
        """
        if config.options.replay_tracking:
            # We only consider requests with piwik.php, ppms.php, js/ or
            # js/tracker.php which don't need host to be imported
            return self._resolve_when_replay_tracking(hit)
        else:
            # Workaround for empty Host bug issue #126
            if hit.host.strip() == "":
                hit.host = "no-hostname-found-in-log"
            return self._resolve_by_host(hit)

    def check_format(self, format):
        if config.options.replay_tracking:
            pass
        elif (
            format.regex is not None
            and "host" not in format.regex.groupindex
            and not config.options.log_hostname
        ):
            fatal_error(
                "the selected log format doesn't include the hostname: you must "
                "specify the Piwik PRO App ID with the --idsite flag "
                "or host with --log-hostname flag"
            )


HitArgsConfig = collections.namedtuple("HitArgsConfig", ["hit", "path", "site_id", "main_url"])


class HitArgsGenerator:
    def __init__(self, base, rules):
        self.base = base
        self.rules = rules

    def generate(self, args_config):
        new_base = copy.deepcopy(self.base)
        for rule in self.rules:
            new_base.update(rule.execute(args_config, new_base))
        return new_base


class ReplayTrackingRule:
    def execute(self, args_config, initial_args=None):
        args = initial_args or {}
        if config.options.replay_tracking:
            # prevent request to be force recorded when option replay-tracking
            args["rec"] = "0"
        else:
            # only prepend main url / host if it's a path
            url_prefix = (
                self._get_host_with_protocol(args_config.hit.host, args_config.main_url)
                if hasattr(args_config.hit, "host")
                else args_config.main_url
            )
            url = (url_prefix if args_config.path.startswith("/") else "") + args_config.path[:1024]

            args["url"] = url
            urlref = args_config.hit.referrer[:1024]
            if len(urlref) > 0:
                args["urlref"] = urlref
        return args

    def _get_host_with_protocol(self, host, main_url):
        if "://" not in host:
            parts = urllib.parse.urlparse(main_url)
            host = parts.scheme + "://" + host
        return host


class HitArgsRule:
    def execute(self, args_config, initial_args=None):
        args = initial_args or {}
        # idsite is already determined by resolver
        hit_args = copy.deepcopy(args_config.hit.args)
        if "idsite" in hit_args:
            del hit_args["idsite"]

        args.update(hit_args)

        if args_config.hit.is_download:
            args["download"] = args["url"]

        if config.options.enable_bots:
            args["bots"] = "1"
        return args


class DownloadsRule:
    def execute(self, args_config, initial_args=None):
        args = initial_args or {}
        if args_config.hit.is_download:
            args["download"] = args["url"]
        return args


class BotsRule:
    def execute(self, args_config, initial_args=None):
        args = initial_args or {}
        if config.options.enable_bots:
            args["bots"] = "1"
        return args


class ErrorOrRedirectRule:
    def execute(self, args_config, initial_args=None):
        args = initial_args or {}
        if args_config.hit.is_error or args_config.hit.is_error:
            args["action_name"] = "%s%sURL = %s%s" % (
                args_config.hit.status,
                config.options.title_category_delimiter,
                urllib.parse.quote(args["url"], ""),
                (
                    "%sFrom = %s"
                    % (
                        config.options.title_category_delimiter,
                        urllib.parse.quote(args["urlref"], ""),
                    )
                    if "urlref" in args
                    else ""
                ),
            )
        return args


class MiscHitItemsRule:
    def execute(self, args_config, initial_args=None):
        args = initial_args or {}

        if args_config.hit.generation_time_milli > 0:
            args["gt_ms"] = str(int(args_config.hit.generation_time_milli))

        if args_config.hit.event_category and args_config.hit.event_action:
            args["e_c"] = args_config.hit.event_category
            args["e_a"] = args_config.hit.event_action

            if args_config.hit.event_name:
                args["e_n"] = args_config.hit.event_name

        if args_config.hit.length:
            args["bw_bytes"] = str(args_config.hit.length)

        # convert custom variable args to JSON
        if "cvar" in args and not isinstance(args["cvar"], str):
            args["cvar"] = json.dumps(args["cvar"])

        if "_cvar" in args and not isinstance(args["_cvar"], str):
            args["_cvar"] = json.dumps(args["_cvar"])

        # If web log analytics is enabled, sending tracking client name and version
        if not config.options.replay_tracking:
            args["ts_n"] = TRACKING_CLIENT_NAME
            args["ts_v"] = TRACKING_CLIENT_VERSION

        if config.options.debug_tracker:
            args["debug"] = "1"
        return args


class Recorder:
    """
    A Recorder fetches hits from the Queue and inserts them into Piwik Pro using
    the API.
    """

    recorders = []

    def __init__(self):
        self.queue = queue.Queue(maxsize=2)

        # if bulk tracking disabled, make sure we can store hits outside of the Queue
        if config.options.disable_bulk_tracking:
            self.unrecorded_hits = []

    @classmethod
    def launch(cls, recorder_count):
        """
        Launch a bunch of Recorder objects in a separate thread.
        """
        for i in range(recorder_count):
            recorder = Recorder()
            cls.recorders.append(recorder)
            run = recorder._run_bulk
            if config.options.disable_bulk_tracking:
                run = recorder._run_single
            t = threading.Thread(target=run)

            t.daemon = True
            t.start()
            logging.debug("Launched recorder")

    @classmethod
    def add_hits(cls, all_hits):
        """
        Add a set of hits to the recorders queue.
        """
        # Organize hits so that one client IP will always use the same queue.
        # We have to do this so visits from the same IP will be added in the right order.
        hits_by_client = [[] for r in cls.recorders]
        for hit in all_hits:
            hits_by_client[hit.get_visitor_id_hash() % len(cls.recorders)].append(hit)

        for i, recorder in enumerate(cls.recorders):
            recorder.queue.put(hits_by_client[i])

    @classmethod
    def wait_empty(cls):
        """
        Wait until all recorders have an empty queue.
        """
        for recorder in cls.recorders:
            recorder._wait_empty()

    def _run_bulk(self):
        while True:
            self._throttle()
            try:
                hits = self.queue.get()
            except Exception:
                # TODO: we should log something here, however when this happens,
                # logging.etc will throw
                return

            if len(hits) > 0:
                try:
                    self._record_hits(hits)
                except PiwikHttpBase.Error as e:
                    fatal_error(
                        e, hits[0].filename, hits[0].lineno
                    )  # approximate location of error
            self.queue.task_done()

    def _run_single(self):
        while True:
            self._throttle()
            self.unrecorded_hits = self.queue.get()
            for hit in self.unrecorded_hits:
                try:
                    self._record_hits([hit], True)
                except PiwikHttpBase.Error as e:
                    fatal_error(e, hit.filename, hit.lineno)
            self.queue.task_done()

    def _throttle(self):
        if config.options.sleep_between_requests_ms is not False:
            time.sleep(config.options.sleep_between_requests_ms / 1000)

    def _wait_empty(self):
        """
        Wait until the queue is empty.
        """
        while True:
            if self.queue.empty():
                # We still have to wait for the last queue item being processed
                # (queue.empty() returns True before queue.task_done() is
                # called).
                self.queue.join()
                return
            time.sleep(1)

    def date_to_piwik(self, date):
        date, time = date.isoformat(sep=" ").split()
        return "%s %s" % (date, time.replace("-", ":"))

    def _get_hit_args(self, hit):
        """
        Returns the args used in tracking a hit, without the token_auth.
        """
        site_id, main_url = resolver.resolve(hit)
        if site_id is None:
            # This hit doesn't match any known Piwik PRO site.
            if config.options.replay_tracking:
                stats.piwik_sites_ignored.add("unrecognized App ID %s" % hit.args.get("idsite"))
            else:
                try:
                    stats.piwik_sites_ignored.add(hit.host)
                except AttributeError:
                    stats.piwik_sites_ignored.add(resolver.initial_site_id)
            stats.count_lines_no_site.increment()
            return {}

        stats.dates_recorded.add(hit.date.date())

        path = hit.path
        if hit.query_string and not config.options.strip_query_string:
            path += config.options.query_string_delimiter + hit.query_string

        # handle custom variables before generating args dict
        if config.options.enable_bots:
            if hit.is_robot:
                hit.add_visit_custom_var("Bot", hit.user_agent)
            else:
                hit.add_visit_custom_var("Not-Bot", hit.user_agent)

        hit.add_page_custom_var("HTTP-code", hit.status)

        args_generator = HitArgsGenerator(
            {
                "rec": "1",
                "apiv": "1",
                "cip": hit.ip,
                "cdt": self.date_to_piwik(hit.date),
                "idsite": site_id,
                "queuedtracking": "0",
                "dp": "0" if config.options.reverse_dns else "1",
                "ua": hit.user_agent,
            },
            [
                ReplayTrackingRule(),
                HitArgsRule(),
                DownloadsRule(),
                BotsRule(),
                ErrorOrRedirectRule(),
                MiscHitItemsRule(),
            ],
        )

        args = args_generator.generate(HitArgsConfig(hit, path, site_id, main_url))
        return UrlHelper.convert_array_args(args)

    def _record_hits(self, hits, single=False):
        """
        Inserts several hits into Piwik PRO.
        """
        hit_count = 0
        if not config.options.dry_run:
            if single:
                assert len(hits) == 1
                headers = None
                data = None

                args = dict(
                    (k, v.encode(config.options.encoding) if isinstance(v, str) else v)
                    for (k, v) in self._get_hit_args(hits[0]).items()
                )
                hit_count = int(len(args) > 0)
            else:
                headers = {"Content-type": "application/json"}
                data = {"requests": []}
                args = {}
                for hit in hits:
                    next_hit = self._get_hit_args(hit)
                    if len(next_hit) > 0:
                        data["requests"].append(next_hit)
                        hit_count += 1

            if hit_count > 0:
                try:
                    response = piwik.call(
                        config.options.piwik_tracker_endpoint_path,
                        args=args,
                        expected_content=None,
                        headers=headers,
                        data=data,
                        on_failure=self._on_tracking_failure,
                    )

                    if config.options.debug_tracker:
                        logging.debug("tracker response:\n%s" % response)

                except PiwikHttpBase.Error as e:
                    if e.code == 400:
                        fatal_error(
                            "Server returned status 400 (Bad Request).",
                            hits[0].filename,
                            hits[0].lineno,
                        )

                    raise

        stats.count_lines_recorded.advance(hit_count)

    def _is_json(self, result):
        try:
            json.loads(result)
            return True
        except ValueError:
            return False

    def _on_tracking_failure(self, response, data):
        """
        Removes the successfully tracked hits from the request payload so
        they are not logged twice.
        """
        try:
            response = json.loads(response)
        except Exception:
            # the response should be in JSON,
            # but in case it can't be parsed just try another attempt
            logging.debug("cannot parse tracker response, should be valid JSON")
            return response

        # remove the successfully tracked hits from payload
        tracked = response["tracked"]
        data["requests"] = data["requests"][tracked:]

        return response["message"]


class Hit:
    """
    It's a simple container.
    """

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        super(Hit, self).__init__()

        if config.options.force_lowercase_path:
            self.full_path = self.full_path.lower()

    def get_visitor_id_hash(self):
        visitor_id = self.ip

        if config.options.replay_tracking:
            for param_name_to_use in ["uid", "cid", "_id", "cip"]:
                if param_name_to_use in self.args:
                    visitor_id = self.args[param_name_to_use]
                    break

        return abs(hash(visitor_id))

    def add_page_custom_var(self, key, value):
        """
        Adds a page custom variable to this Hit.
        """
        self._add_custom_var(key, value, "cvar")

    def add_visit_custom_var(self, key, value):
        """
        Adds a visit custom variable to this Hit.
        """
        self._add_custom_var(key, value, "_cvar")

    def _add_custom_var(self, key, value, api_arg_name):
        if api_arg_name not in self.args:
            self.args[api_arg_name] = {}

        if isinstance(self.args[api_arg_name], str):
            logging.debug(
                "Ignoring custom %s variable addition [ %s = %s ], custom var already set to"
                " string." % (api_arg_name, key, value)
            )
            return

        index = len(self.args[api_arg_name]) + 1
        self.args[api_arg_name][index] = [key, value]


class Parser:
    """
    The Parser parses the lines in a specified file and inserts them into
    a Queue.
    """

    def __init__(self):
        self.check_methods = [
            method
            for name, method in inspect.getmembers(self, predicate=inspect.ismethod)
            if name.startswith("check_")
        ]

    # All check_* methods are called for each hit and must return True if the
    # hit can be imported, False otherwise.

    def check_hostname(self, hit):
        # Check against config.hostnames.
        if not hasattr(hit, "host") or not config.options.hostnames:
            return True

        # Accept the hostname only if it matches one pattern in the list.
        result = any(fnmatch.fnmatch(hit.host, pattern) for pattern in config.options.hostnames)
        if not result:
            stats.count_lines_hostname_skipped.increment()
        return result

    def check_static(self, hit):
        filename = hit.path.split("/")[-1]

        if hit.extension in STATIC_EXTENSIONS or filename in STATIC_FILES:
            if config.options.enable_static:
                hit.is_download = True
                return True
            else:
                stats.count_lines_static.increment()
                return False
        return True

    def check_download(self, hit):
        if hit.extension in config.options.download_extensions:
            stats.count_lines_downloads.increment()
            hit.is_download = True
            return True
        # the file is not in the white-listed downloads
        # if it's a know download file, we shall skip it
        elif hit.extension in DOWNLOAD_EXTENSIONS:
            stats.count_lines_skipped_downloads.increment()
            return False
        return True

    def check_user_agent(self, hit):
        user_agent = hit.user_agent.lower()
        for s in itertools.chain(EXCLUDED_USER_AGENTS, config.options.excluded_useragents):
            if s in user_agent:
                if config.options.enable_bots:
                    hit.is_robot = True
                    return True
                else:
                    stats.count_lines_skipped_user_agent.increment()
                    return False
        return True

    def check_http_error(self, hit):
        if hit.status[0] in ("4", "5"):
            if config.options.replay_tracking:
                # process error logs for replay tracking,
                # since we don't care if Piwik PRO error-ed the first time
                return True
            elif config.options.enable_http_errors:
                hit.is_error = True
                return True
            else:
                stats.count_lines_skipped_http_errors.increment()
                return False
        return True

    def check_http_redirect(self, hit):
        if hit.status[0] == "3" and hit.status != "304":
            if config.options.enable_http_redirects:
                hit.is_redirect = True
                return True
            else:
                stats.count_lines_skipped_http_redirects.increment()
                return False
        return True

    def check_path(self, hit):
        for excluded_path in config.options.excluded_paths:
            if fnmatch.fnmatch(hit.path, excluded_path):
                return False
        # By default, all paths are included.
        if config.options.included_paths:
            for included_path in config.options.included_paths:
                if fnmatch.fnmatch(hit.path, included_path):
                    return True
            return False
        return True

    @staticmethod
    def _try_match(format, lineOrFile):
        match = None
        try:
            if isinstance(lineOrFile, str):
                match = format.check_format_line(lineOrFile)
            else:
                match = format.check_format(lineOrFile)
        except Exception:
            logging.debug("Error in format checking: %s", traceback.format_exc())
            pass
        return match

    @staticmethod
    def check_format(lineOrFile):
        format = False
        format_groups = 0
        for name, candidate_format in FORMATS.items():
            logging.debug("Check format %s", name)

            # skip auto detection for formats that can't be detected automatically
            if name == "ovh":
                continue

            match = Parser._try_match(candidate_format, lineOrFile)
            if match:
                logging.debug("Format %s matches", name)

                # compare format groups if this *BaseFormat has groups() method
                try:
                    # if there's more info in this match, use this format
                    match_groups = len(match.groups())

                    logging.debug("Format match contains %d groups" % match_groups)

                    if format_groups < match_groups:
                        format = candidate_format
                        format_groups = match_groups
                except AttributeError:
                    format = candidate_format
            else:
                logging.debug("Format %s does not match", name)

        # if the format is W3cExtendedFormat,
        # check if the logs are from IIS and if so, issue a warning if the
        # --w3c-time-taken-milli option isn't set
        if isinstance(format, W3cExtendedFormat):
            format.check_for_iis_option()

        return format

    @staticmethod
    def detect_format(file):
        """
        Return the best matching format for this file, or None if none was found.
        """
        logging.debug("Detecting the log format")

        format = False

        # check the format using the file (for formats like the W3cExtendedFormat one)
        format = Parser.check_format(file)

        # check the format using the first N lines (to avoid irregular ones)
        lineno = 0
        limit = 100000
        while not format and lineno < limit:
            line = file.readline()
            if not line:  # if at eof, don't keep looping
                break

            lineno = lineno + 1

            logging.debug("Detecting format against line %i" % lineno)
            format = Parser.check_format(line)

        try:
            file.seek(0)
        except IOError:
            pass

        if not format:
            fatal_error(
                "cannot automatically determine the log format using the first %d lines of the log"
                " file. " % limit
                + "\nMaybe try specifying the format with the --log-format-name command line"
                " argument."
            )
            return

        logging.debug("Format %s is the best match", format.name)
        return format

    def is_filtered(self, hit):
        host = None
        if hasattr(hit, "host"):
            host = hit.host
        else:
            try:
                host = urllib.parse.urlparse(hit.path).hostname
            except Exception:
                pass

        if host:
            if (
                config.options.exclude_host
                and len(config.options.exclude_host) > 0
                and host in config.options.exclude_host
            ):
                return (True, "host matched --exclude-host")

            if (
                config.options.include_host
                and len(config.options.include_host) > 0
                and host not in config.options.include_host
            ):
                return (True, "host did not match --include-host")

        if config.options.exclude_older_than and hit.date < config.options.exclude_older_than:
            return (True, "date is older than --exclude-older-than")

        if config.options.exclude_newer_than and hit.date > config.options.exclude_newer_than:
            return (True, "date is newer than --exclude-newer-than")

        return (False, None)

    @staticmethod
    def invalid_line(line, reason):
        stats.count_lines_invalid.increment()
        if config.options.debug >= 2:
            logging.debug("Invalid line detected (%s): %s" % (reason, line))

    @staticmethod
    def filtered_line(line, reason):
        stats.count_lines_filtered.increment()
        if config.options.debug >= 2:
            logging.debug("Filtered line out (%s): %s" % (reason, line))

    def _get_file_and_filename(self, filename):
        if filename == "-":
            return "(stdin)", sys.stdin
        else:
            if not os.path.exists(filename):
                print(
                    "\n=====> Warning: File %s does not exist <=====" % filename,
                    file=sys.stderr,
                )
                return filename, None
            else:
                if filename.endswith(".bz2"):
                    open_func = bz2.open
                elif filename.endswith(".gz"):
                    open_func = gzip.open
                else:
                    open_func = open

                file = open_func(
                    filename,
                    mode="rt",
                    encoding=config.options.encoding,
                    errors="surrogateescape",
                )
                return filename, file

    # Returns True if format was configured
    def _configure_format(self, file):
        if config.format:
            # The format was explicitly specified.
            format = config.format

            if isinstance(format, W3cExtendedFormat):
                format.create_regex(file)

                if format.regex is None:
                    fatal_error(
                        "File is not in the correct format, is there a '#Fields:' line? "
                        "If not, use the --w3c-fields option."
                    )
        else:
            # If the file is empty, don't bother.
            data = file.read(100)
            if len(data.strip()) == 0:
                return False
            try:
                file.seek(0)
            except IOError:
                pass

            format = self.detect_format(file)
            if format is None:
                fatal_error(
                    "Cannot guess the logs format. Please give one using "
                    "either the --log-format-name or --log-format-regex option"
                )
        return format

    def _validate_format(self, format):
        # Make sure the format is compatible with the resolver.
        resolver.check_format(format)
        if config.options.dump_log_regex:
            logging.info("Using format '%s'." % format.name)
            if format.regex:
                logging.info("Regex being used: %s" % format.regex.pattern)
            else:
                logging.info("Format %s does not use a regex to parse log lines." % format.name)
            logging.info("--dump-log-regex option used, aborting log import.")
            os._exit(0)

    def parse(self, filename):  # noqa C901
        """
        Parse the specified filename and insert hits in the queue.
        """
        filename, file = self._get_file_and_filename(filename)

        if config.options.show_progress:
            print(("Parsing log %s..." % filename))

        format = self._configure_format(file)
        if not format:
            return

        self._validate_format(format)
        valid_lines_count = 0

        hits = []
        lineno = -1
        while True:
            line = file.readline()
            if not line:
                break
            lineno = lineno + 1

            stats.count_lines_parsed.increment()
            if stats.count_lines_parsed.value <= config.options.skip:
                continue

            match = format.match(line)
            if not match:
                self.invalid_line(line, "line did not match")
                continue

            valid_lines_count = valid_lines_count + 1
            if (
                config.options.debug_request_limit
                and valid_lines_count >= config.options.debug_request_limit
            ):
                if len(hits) > 0:
                    Recorder.add_hits(hits)
                logging.info("Exceeded limit specified in --debug-request-limit, exiting.")
                return

            hit = Hit(
                filename=filename,
                lineno=lineno,
                status=format.get("status"),
                full_path=format.get("path"),
                is_download=False,
                is_robot=False,
                is_error=False,
                is_redirect=False,
                args={},
            )

            if config.options.regex_group_to_page_cvars_map:
                self._add_custom_vars_from_regex_groups(
                    hit, format, config.options.regex_group_to_page_cvars_map, True
                )

            if config.options.regex_group_to_visit_cvars_map:
                self._add_custom_vars_from_regex_groups(
                    hit, format, config.options.regex_group_to_visit_cvars_map, False
                )

            if config.options.regex_groups_to_ignore:
                format.remove_ignored_groups(config.options.regex_groups_to_ignore)

            # Add http method page cvar
            try:
                httpmethod = format.get("method")
                if config.options.track_http_method and httpmethod != "-":
                    hit.add_page_custom_var("HTTP-method", httpmethod)
            except Exception:
                pass

            try:
                hit.query_string = format.get("query_string")
                hit.path = hit.full_path
            except BaseFormatException:
                hit.path, _, hit.query_string = hit.full_path.partition(
                    config.options.query_string_delimiter
                )

            # W3cExtendedFormat detaults to - when there is no query string,
            # but we want empty string
            if hit.query_string == "-":
                hit.query_string = ""

            hit.extension = hit.path.rsplit(".")[-1].lower()

            try:
                hit.referrer = format.get("referrer")

                if hit.referrer.startswith('"'):
                    hit.referrer = hit.referrer[1:-1]
            except BaseFormatException:
                hit.referrer = ""
            if hit.referrer == "-":
                hit.referrer = ""

            try:
                hit.user_agent = format.get("user_agent")

                # in case a format parser included enclosing quotes, remove them so they are not
                # sent to Piwik
                if hit.user_agent.startswith('"'):
                    hit.user_agent = hit.user_agent[1:-1]
            except BaseFormatException:
                hit.user_agent = ""

            hit.ip = format.get("ip")
            try:
                hit.length = int(format.get("length"))
            except (ValueError, BaseFormatException):
                # Some lines or formats don't have a length (e.g. 304 redirects, W3C logs)
                hit.length = 0

            try:
                hit.generation_time_milli = float(format.get("generation_time_milli"))
            except (ValueError, BaseFormatException):
                try:
                    hit.generation_time_milli = float(format.get("generation_time_micro")) / 1000
                except (ValueError, BaseFormatException):
                    try:
                        hit.generation_time_milli = float(format.get("generation_time_secs")) * 1000
                    except (ValueError, BaseFormatException):
                        hit.generation_time_milli = 0

            if config.options.log_hostname:
                hit.host = config.options.log_hostname
            else:
                try:
                    hit.host = format.get("host").lower().strip(".")

                    if hit.host.startswith('"'):
                        hit.host = hit.host[1:-1]
                except BaseFormatException:
                    # Some formats have no host.
                    pass

            # Add userid
            try:
                hit.userid = None

                userid = format.get("userid")
                if userid != "-":
                    hit.args["uid"] = hit.userid = userid
            except Exception:
                pass

            # add event info
            try:
                hit.event_category = hit.event_action = hit.event_name = None

                hit.event_category = format.get("event_category")
                hit.event_action = format.get("event_action")

                hit.event_name = format.get("event_name")
                if hit.event_name == "-":
                    hit.event_name = None
            except Exception:
                pass

            # Check if the hit must be excluded.
            if not all((method(hit) for method in self.check_methods)):
                continue

            # Parse date.
            # We parse it after calling check_methods as it's quite CPU hungry, and
            # we want to avoid that cost for excluded hits.
            date_string = format.get("date")
            try:
                hit.date = datetime.datetime.strptime(date_string, format.date_format)
                hit.date += datetime.timedelta(seconds=config.options.seconds_to_add_to_date)
            except ValueError as e:
                self.invalid_line(line, "invalid date or invalid format: %s" % str(e))
                continue

            # Parse timezone and subtract its value from the date
            try:
                timezone = format.get("timezone").replace(":", "")
                if timezone:
                    hit.date -= TimeHelper.timedelta_from_timezone(timezone)
            except BaseFormatException:
                pass
            except ValueError:
                self.invalid_line(line, "invalid timezone")
                continue

            if config.options.replay_tracking:
                # we need a query string and we only consider requests with piwik.php,
                # ppms.php, js/ or js/tracker.php
                if not hit.query_string or not self.is_hit_for_tracker(hit):
                    self.invalid_line(
                        line,
                        "no query string, or "
                        + hit.path.lower()
                        + " does not end with piwik.php, ppms.php, js/ or js/tracker.php",
                    )
                    continue

                query_arguments = urllib.parse.parse_qs(hit.query_string)
                if "idsite" not in query_arguments:
                    self.invalid_line(line, "missing idsite")
                    continue

                hit.args.update((k, v.pop()) for k, v in query_arguments.items())

                if config.options.seconds_to_add_to_date:
                    for param in ["_idts", "_viewts", "_ects", "_refts"]:
                        if param in hit.args:
                            hit.args[param] = str(
                                int(hit.args[param]) + config.options.seconds_to_add_to_date
                            )

            (is_filtered, reason) = self.is_filtered(hit)
            if is_filtered:
                self.filtered_line(line, reason)
                continue

            hits.append(hit)

            if len(hits) >= config.options.recorder_max_payload_size * len(Recorder.recorders):
                Recorder.add_hits(hits)
                hits = []

        # add last chunk of hits
        if len(hits) > 0:
            Recorder.add_hits(hits)

    def is_hit_for_tracker(self, hit):
        filesToCheck = ["piwik.php", "ppms.php", "/js/", "/js/tracker.php"]
        if config.options.replay_tracking_expected_tracker_file:
            filesToCheck = [config.options.replay_tracking_expected_tracker_file]

        lowerPath = hit.path.lower()
        for file in filesToCheck:
            if lowerPath.endswith(file):
                return True
        return False

    def _add_custom_vars_from_regex_groups(self, hit, format, groups, is_page_var):
        for group_name, custom_var_name in groups.items():
            if group_name in format.get_all():
                value = format.get(group_name)

                # don't track the '-' empty placeholder value
                if value == "-":
                    continue

                if is_page_var:
                    hit.add_page_custom_var(custom_var_name, value)
                else:
                    hit.add_visit_custom_var(custom_var_name, value)


def main():
    """
    Start the importing process.
    """
    stats.set_time_start()

    if config.options.show_progress:
        stats.start_monitor()

    Recorder.launch(config.options.recorders)

    try:
        for filename in config.filenames:
            parser.parse(filename)

        Recorder.wait_empty()
    except KeyboardInterrupt:
        pass

    stats.set_time_stop()

    if config.options.show_progress:
        stats.stop_monitor()

    stats.print_summary()


def fatal_error(error, filename=None, lineno=None):
    print("Fatal error: %s" % error, file=sys.stderr)
    if filename and lineno is not None:
        print(
            'You can restart the import of "%s" from the point it failed by '
            "specifying --skip=%d on the command line.\n" % (filename, lineno),
            file=sys.stderr,
        )
    os._exit(1)


# Hack to work around usage of globals in this script and tests
if not os.getenv("PYTEST_SESSION"):
    config = Configuration()
    # The Piwik PRO object depends on the config object, so we have to create
    # it after creating the configuration.
    piwik = PiwikHttpUrllib()
    # The init_token_auth method may need the piwik option, so we must call
    # it after creating the piwik object.
    config.init_token_auth()
    stats = Statistics()
    resolver = config.get_resolver()
    parser = Parser()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

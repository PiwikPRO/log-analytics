# vim: et sw=4 ts=4:
import datetime
import io
import json
import logging
import os
import re
import threading
import time
import urllib.error
from collections import OrderedDict
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from piwik_pro_log_analytics import import_logs


# utility functions
def add_junk_to_file(path):
    file = open(path)
    contents = file.read()
    file.close()

    file = open("tmp.log", "w")
    file.write(contents + " junk")
    file.close()

    return "tmp.log"


def add_multiple_spaces_to_file(path):
    file = open(path)
    contents = file.read()
    file.close()

    # replace spaces that aren't between " quotes
    contents = contents.split('"')
    for i in range(0, len(contents), 2):
        contents[i] = re.sub(" ", "  ", contents[i])
    contents = '"'.join(contents)
    import_logs.logging.debug(contents)

    assert "  " in contents  # sanity check

    file = open("tmp.log", "w")
    file.write(contents)
    file.close()

    return "tmp.log"


def use_ipv6_in_file(path):
    file = open(path)
    contents = file.read()
    file.close()

    if "1.2.3.4" not in contents:
        raise RuntimeError("could not find ipv4 IP in " + path + ", make sure the IP 1.2.3.4 is used for tests")

    contents = contents.replace("1.2.3.4", "0:0:0:0:0:ffff:7b2d:4359")

    file = open("tmp.log", "w")
    file.write(contents)
    file.close()

    return "tmp.log"


def tearDownModule():
    if os.path.exists("tmp.log"):
        os.remove("tmp.log")


class TestFormatDetection:
    def _test(self, format_name, log_file=None):
        if log_file is None:
            log_file = "logs/%s.log" % format_name

        file = open(log_file)
        import_logs.config = Config()
        format = import_logs.Parser.detect_format(file)
        assert format is not None
        assert format.name == format_name

    def _test_junk(self, format_name, log_file=None):
        if log_file is None:
            log_file = "logs/%s.log" % format_name

        tmp_path = add_junk_to_file(log_file)

        file = open(tmp_path)
        import_logs.config = Config()
        format = import_logs.Parser.detect_format(file)
        assert format is not None
        assert format.name == format_name

    def _test_multiple_spaces(self, format_name, log_file=None):
        if log_file is None:
            log_file = "logs/%s.log" % format_name

        tmp_path = add_multiple_spaces_to_file(log_file)

        file = open(tmp_path)
        import_logs.config = Config()
        format = import_logs.Parser.detect_format(file)
        assert format is not None
        assert format.name == format_name

    def _test_ipv6(self, format_name, log_file=None):
        if log_file is None:
            log_file = "logs/%s.log" % format_name

        tmp_path = use_ipv6_in_file(log_file)

        # test correct format is detected first
        file = open(tmp_path)
        import_logs.config = Config()
        format = import_logs.Parser.detect_format(file)
        assert format is not None
        assert format.name == format_name

        # then parse the file and test the IP is parsed correctly
        groups = parse_log_file_line(format_name, tmp_path)
        assert groups["ip"] == "0:0:0:0:0:ffff:7b2d:4359"

    def test_format_detection(self):
        for format_name in import_logs.FORMATS.keys():
            # w3c extended tested by iis and netscaler log files; amazon cloudfront tested later
            if (
                format_name == "w3c_extended"
                or format_name == "amazon_cloudfront"
                or format_name == "ovh"
                or format_name == "gandi"
                or format_name == "haproxy"
                or format_name == "incapsula_w3c"
            ):
                continue

            # 'Testing autodetection of format ' + format_name
            self._test(format_name)

            # 'Testing autodetection of format ' + format_name + ' w/ garbage at end of line'
            self._test_junk(format_name)

            # 'Testing autodetection of format ' + format_name + '
            # when multiple spaces separate fields'
            self._test_multiple_spaces(format_name)

            # 'Testing parsing of IPv6 address with format ' + format_name
            self._test_ipv6(format_name)

        # add tests for amazon cloudfront (normal web + rtmp)
        # 'Testing autodetection of amazon cloudfront (web) logs.'
        self._test("amazon_cloudfront", "logs/amazon_cloudfront_web.log")

        # ' Testing autodetection of amazon cloudfront (web) logs w/ garbage at end of line'
        self._test_junk("amazon_cloudfront", "logs/amazon_cloudfront_web.log")

        # 'Testing autodetection of format amazon cloudfront (web)
        # logs when multiple spaces separate fields'
        self._test_multiple_spaces("amazon_cloudfront", "logs/amazon_cloudfront_web.log")

        # 'Testing autodetection of amazon cloudfront (rtmp) logs.'
        self._test("amazon_cloudfront", "logs/amazon_cloudfront_rtmp.log")

        # 'Testing autodetection of amazon cloudfront (rtmp) logs w/ garbage at end of line.'
        self._test_junk("amazon_cloudfront", "logs/amazon_cloudfront_rtmp.log")

        # 'Testing autodetection of format amazon cloudfront (rtmp)
        # logs when multiple spaces separate fields'
        self._test_multiple_spaces("amazon_cloudfront", "logs/amazon_cloudfront_rtmp.log")


class Options(object):
    """Mock config options necessary to run checkers from Parser class."""

    def __init__(self):
        self.debug = False
        self.encoding = "utf-8"
        self.log_hostname = "foo"
        self.query_string_delimiter = "?"
        self.piwik_token_auth = False
        self.piwik_url = "http://example.com"
        self.recorder_max_payload_size = 200
        self.replay_tracking = True
        self.show_progress = False
        self.skip = False
        self.hostnames = []
        self.excluded_paths = []
        self.excluded_useragents = []
        self.enable_bots = []
        self.force_lowercase_path = False
        self.included_paths = []
        self.enable_http_errors = False
        self.download_extensions = "doc,pdf"
        self.custom_w3c_fields = {}
        self.dump_log_regex = False
        self.w3c_time_taken_in_millisecs = False
        self.w3c_fields = None
        self.w3c_field_regexes = {}
        self.regex_group_to_visit_cvars_map = {}
        self.regex_group_to_page_cvars_map = {}
        self.regex_groups_to_ignore = None
        self.replay_tracking_expected_tracker_file = "piwik.php"
        self.debug_request_limit = None
        self.exclude_host = []
        self.include_host = []
        self.exclude_older_than = None
        self.exclude_newer_than = None
        self.track_http_method = True
        self.seconds_to_add_to_date = 0
        self.request_suffix = None


class Config(object):
    """Mock configuration."""

    def __init__(self):
        self.options = Options()
        self.format = import_logs.FORMATS["ncsa_extended"]


class Resolver(object):
    """Mock resolver which doesn't check connection to real piwik."""

    def check_format(self, format_):
        pass


class Recorder(object):
    """Mock recorder which collects hits but doesn't put their in database."""

    recorders = []

    @classmethod
    def add_hits(cls, hits):
        cls.recorders.extend(hits)


class Piwik(object):
    """Mock piwik api requests for StaticResolver tests"""

    def auth_call_api(cls, method, **kwargs):
        return {
            "data": {
                "id": "194edb22-394a-48e5-aed8-0797ab29d2ae",
                "attributes": {"urls": ["https://example.com"]},
            }
        }


def test_replay_tracking_seconds_to_add_to_date():
    """Test data parsing from sample log file."""
    file_ = "logs/logs_to_tests.log"

    import_logs.stats = import_logs.Statistics()
    import_logs.config = Config()
    import_logs.config.options.seconds_to_add_to_date = 3600
    import_logs.resolver = Resolver()
    import_logs.Recorder = Recorder()
    import_logs.parser = import_logs.Parser()
    import_logs.parser.parse(file_)

    hits = [hit.args for hit in import_logs.Recorder.recorders]

    assert hits[0]["_idts"] == str(1360047661 + 3600)
    assert hits[0]["_viewts"] == str(1360047661 + 3600)
    assert hits[0]["_refts"] == str(1360047661 + 3600)
    assert hits[0]["_ects"] == str(1360047634 + 3600)

    assert hits[1]["_idts"] == str(1360047661 + 3600)
    assert hits[1]["_viewts"] == str(1360047661 + 3600)
    assert hits[1]["_refts"] == str(1360047661 + 3600)
    assert hits[1]["_ects"] == str(1360047534 + 3600)

    assert hits[2]["_idts"] == str(1360047661 + 3600)
    assert hits[2]["_viewts"] == str(1360047661 + 3600)
    assert hits[2]["_refts"] == str(1360047661 + 3600)
    assert hits[2]["_ects"] == str(1360047614 + 3600)


def test_replay_tracking_arguments():
    """Test data parsing from sample log file."""
    file_ = "logs/logs_to_tests.log"

    import_logs.stats = import_logs.Statistics()
    import_logs.config = Config()
    import_logs.resolver = Resolver()
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.parser.parse(file_)

    hits = [hit.args for hit in import_logs.Recorder.recorders]

    assert hits[0]["_idn"] == "0"
    assert hits[0]["ag"] == "1"
    assert hits[0]["_viewts"] == "1360047661"
    assert hits[0]["urlref"] == "http://clearcode.cc/welcome"
    assert hits[0]["_ref"] == "http://piwik.org/thank-you-all/"
    assert hits[0]["_idts"] == "1360047661"
    assert hits[0]["java"] == "1"
    assert hits[0]["res"] == "1680x1050"
    assert hits[0]["idsite"] == "1"
    assert hits[0]["realp"] == "0"
    assert hits[0]["wma"] == "1"
    assert hits[0]["_idvc"] == "1"
    assert hits[0]["action_name"] == "Clearcode - Web and Mobile Development | Technology With Passion"
    assert hits[0]["cookie"] == "1"
    assert hits[0]["rec"] == "1"
    assert hits[0]["qt"] == "1"
    assert hits[0]["url"] == "http://clearcode.cc/"
    assert hits[0]["h"] == "17"
    assert hits[0]["m"] == "31"
    assert hits[0]["s"] == "25"
    assert hits[0]["r"] == "983420"
    assert hits[0]["fla"] == "1"
    assert hits[0]["pdf"] == "1"
    assert hits[0]["_id"] == "1da79fc743e8bcc4"
    assert hits[0]["_refts"] == "1360047661"

    assert hits[1]["_idn"] == "0"
    assert hits[1]["ag"] == "1"
    assert hits[1]["_viewts"] == "1360047661"
    assert hits[1]["urlref"] == "http://clearcode.cc/welcome"
    assert hits[1]["_ref"] == "http://piwik.org/thank-you-all/"
    assert hits[1]["_idts"] == "1360047661"
    assert hits[1]["java"] == "1"
    assert hits[1]["res"] == "1680x1050"
    assert hits[1]["idsite"] == "1"
    assert hits[1]["realp"] == "0"
    assert hits[1]["wma"] == "1"
    assert hits[1]["_idvc"] == "1"
    assert hits[1]["action_name"] == "AdviserBrief - Track Your Investments and Plan Financial Future | Clearcode"
    assert hits[1]["cookie"] == "1"
    assert hits[1]["rec"] == "1"
    assert hits[1]["qt"] == "1"
    assert hits[1]["url"] == "http://clearcode.cc/case/adviserbrief-track-your-investments-and-plan-financial-future/"
    assert hits[1]["h"] == "17"
    assert hits[1]["m"] == "31"
    assert hits[1]["s"] == "40"
    assert hits[1]["r"] == "109464"
    assert hits[1]["fla"] == "1"
    assert hits[1]["pdf"] == "1"
    assert hits[1]["_id"] == "1da79fc743e8bcc4"
    assert hits[1]["_refts"] == "1360047661"

    assert hits[2]["_idn"] == "0"
    assert hits[2]["ag"] == "1"
    assert hits[2]["_viewts"] == "1360047661"
    assert hits[2]["urlref"] == "http://clearcode.cc/welcome"
    assert hits[2]["_ref"] == "http://piwik.org/thank-you-all/"
    assert hits[2]["_idts"] == "1360047661"
    assert hits[2]["java"] == "1"
    assert hits[2]["res"] == "1680x1050"
    assert hits[2]["idsite"] == "1"
    assert hits[2]["realp"] == "0"
    assert hits[2]["wma"] == "1"
    assert hits[2]["_idvc"] == "1"
    assert hits[2]["action_name"] == "ATL Apps - American Tailgating League Mobile Android IOS Games | Clearcode"
    assert hits[2]["cookie"] == "1"
    assert hits[2]["rec"] == "1"
    assert hits[2]["qt"] == "1"
    assert hits[2]["url"] == "http://clearcode.cc/case/atl-apps-mobile-android-ios-games/"
    assert hits[2]["h"] == "17"
    assert hits[2]["m"] == "31"
    assert hits[2]["s"] == "46"
    assert hits[2]["r"] == "080064"
    assert hits[2]["fla"] == "1"
    assert hits[2]["pdf"] == "1"
    assert hits[2]["_id"] == "1da79fc743e8bcc4"
    assert hits[2]["_refts"] == "1360047661"


def parse_log_file_line(format_name, file_):
    format = import_logs.FORMATS[format_name]

    import_logs.config.options.custom_w3c_fields = {}

    file = open(file_)
    format.check_format(file)
    file.close()

    return format.get_all()


# check parsing groups
def check_common_groups(groups):
    assert groups["ip"] == "1.2.3.4"
    assert groups["date"] == "10/Feb/2012:16:42:07"
    assert groups["timezone"] == "-0500"
    assert groups["path"] == "/"
    assert groups["status"] == "301"
    assert groups["length"] == "368"
    assert groups["userid"] == "theuser"


def check_ncsa_extended_groups(groups):
    check_common_groups(groups)

    assert groups["referrer"] == "-"
    assert (
        groups["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko)"
        " Chrome/17.0.963.56 Safari/535.11"
    )


def check_common_vhost_groups(groups):
    check_common_groups(groups)

    assert groups["host"] == "www.example.com"


def check_common_complete_groups(groups):
    check_ncsa_extended_groups(groups)

    assert groups["host"] == "www.example.com"


def check_iis_groups(groups):
    assert groups["date"] == "2012-04-01 00:00:13"
    assert groups["path"] == "/foo/bar"
    assert groups["query_string"] == "topCat1=divinity&submit=Search"
    assert groups["ip"] == "1.2.3.4"
    assert groups["referrer"] == "-"
    assert groups["user_agent"] == "Mozilla/5.0+(X11;+U;+Linux+i686;+en-US;+rv:1.9.2.7)+Gecko/20100722+Firefox/3.6.7"
    assert groups["status"] == "200"
    assert groups["length"] == "27028"
    assert groups["host"] == "example.com"

    expected_hit_properties = [
        "date",
        "path",
        "query_string",
        "ip",
        "referrer",
        "user_agent",
        "status",
        "length",
        "host",
        "userid",
        "generation_time_milli",
        "__win32_status",
        "cookie",
        "method",
    ]

    for property_name in groups.keys():
        assert property_name in expected_hit_properties


def check_s3_groups(groups):
    assert groups["host"] == "www.example.com"
    assert groups["date"] == "10/Feb/2012:16:42:07"
    assert groups["timezone"] == "-0500"
    assert groups["ip"] == "1.2.3.4"
    assert groups["userid"] == "arn:aws:iam::179580289999:user/phillip.boss"
    assert groups["path"] == "/index"
    assert groups["status"] == "200"
    assert groups["length"] == "368"
    assert groups["referrer"] == "-"
    assert (
        groups["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko)"
        " Chrome/17.0.963.56 Safari/535.11"
    )


def check_nginx_json_groups(groups):
    assert groups["host"] == "www.piwik.org"
    assert groups["status"] == "200"
    assert groups["ip"] == "1.2.3.4"
    assert groups["length"] == 192
    assert (
        groups["user_agent"] == "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko)"
        " Chrome/24.0.1312.57 Safari/537.17"
    )
    assert groups["date"] == "2013-10-10T16:52:00+02:00"


def check_icecast2_groups(groups):
    check_ncsa_extended_groups(groups)

    assert groups["session_time"] == "1807"


def check_match_groups(format_name, groups):
    symbols = globals()
    check_function = symbols["check_" + format_name + "_groups"]
    return check_function(groups)


def check_ovh_groups(groups):
    check_common_complete_groups(groups)


def check_gandi_groups(groups):
    check_common_complete_groups(groups)


def check_haproxy_groups(groups):
    assert groups["ip"] == "4.3.2.1"
    assert groups["date"] == "25/Sep/2018:06:05:27.584"
    assert groups["path"] == "/user/"
    assert groups["status"] == "200"
    assert groups["length"] == "7456"
    assert groups["method"] == "POST"


# parsing tests
def test_format_parsing():
    # test format regex parses correctly
    def _test(format_name, path):
        groups = parse_log_file_line(format_name, path)
        check_match_groups(format_name, groups)

    # test format regex parses correctly when there's added junk at the end of the line
    def _test_with_junk(format_name, path):
        tmp_path = add_junk_to_file(path)
        _test(format_name, tmp_path)

    for format_name in import_logs.FORMATS.keys():
        # w3c extended tested by IIS and netscaler logs; amazon cloudfront tested individually
        if (
            format_name == "w3c_extended"
            or format_name == "amazon_cloudfront"
            or format_name == "shoutcast"
            or format_name == "elb"
            or format_name == "incapsula_w3c"
        ):
            continue

        # 'Testing parsing of format "%s"' % format_name
        _test(format_name, "logs/" + format_name + ".log")

        # 'Testing parsing of format "%s" with junk appended to path' % format_name
        _test_with_junk(format_name, "logs/" + format_name + ".log")

    # 'Testing parsing of format "common" with ncsa_extended log'
    _test("common", "logs/ncsa_extended.log")


def test_iis_custom_format():
    """test IIS custom format name parsing."""

    file_ = "logs/iis_custom.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {
        "date-local": "date",
        "time-local": "time",
        "cs(Host)": "cs-host",
        "TimeTakenMS": "time-taken",
    }
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["status"] == "200"
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "/products/theproduct"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == "http://example.com/Search/SearchResults.pg?informationRecipient.languageCode.c=en"
    assert hits[0]["args"] == {"cvar": {1: ["HTTP-method", "GET"]}}
    assert hits[0]["generation_time_milli"] == 109
    assert hits[0]["host"] == "foo"
    assert hits[0]["filename"] == "logs/iis_custom.log"
    assert hits[0]["is_redirect"] is False
    assert hits[0]["date"] == datetime.datetime(2012, 8, 15, 17, 0)
    assert hits[0]["lineno"] == 7
    assert hits[0]["ip"] == "70.95.0.0"
    assert hits[0]["query_string"] == ""
    assert hits[0]["path"] == "/Products/theProduct"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/Products/theProduct"
    assert (
        hits[0]["user_agent"] == "Mozilla/5.0 (Linux; Android 4.4.4; SM-G900V Build/KTU84P) AppleWebKit/537.36 (KHTML,"
        " like Gecko) Chrome/39.0.2171.59 Mobile Safari/537.36"
    )

    assert hits[1]["status"] == "301"
    assert hits[1]["is_error"] is False
    assert hits[1]["extension"] == "/topic/hw43061"
    assert hits[1]["is_download"] is False
    assert hits[1]["referrer"] == ""
    assert hits[1]["args"] == {"cvar": {1: ["HTTP-method", "GET"]}}
    assert hits[1]["generation_time_milli"] == 0
    assert hits[1]["host"] == "foo"
    assert hits[1]["filename"] == "logs/iis_custom.log"
    assert hits[1]["is_redirect"] is True
    assert hits[1]["date"] == datetime.datetime(2012, 8, 15, 17, 0)
    assert hits[1]["lineno"] == 8
    assert hits[1]["ip"] == "-"
    assert hits[1]["query_string"] == ""
    assert hits[1]["path"] == "/Topic/hw43061"
    assert hits[1]["is_robot"] is False
    assert hits[1]["full_path"] == "/Topic/hw43061"
    assert (
        hits[1]["user_agent"]
        == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/41.0.2227.1 Safari/537.36"
    )

    assert hits[2]["status"] == "404"
    assert hits[2]["is_error"] is True
    assert hits[2]["extension"] == "/hello/world/6,681965"
    assert hits[2]["is_download"] is False
    assert hits[2]["referrer"] == ""
    assert hits[2]["args"] == {"cvar": {1: ["HTTP-method", "GET"]}}
    assert hits[2]["generation_time_milli"] == 359
    assert hits[2]["host"] == "foo"
    assert hits[2]["filename"] == "logs/iis_custom.log"
    assert hits[2]["is_redirect"] is False
    assert hits[2]["date"] == datetime.datetime(2012, 8, 15, 17, 0)
    assert hits[2]["lineno"] == 9
    assert hits[2]["ip"] == "173.5.0.0"
    assert hits[2]["query_string"] == ""
    assert hits[2]["path"] == "/hello/world/6,681965"
    assert hits[2]["is_robot"] is False
    assert hits[2]["full_path"] == "/hello/world/6,681965"
    assert (
        hits[2]["user_agent"]
        == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/37.0.2062.124 Safari/537.36"
    )


def test_netscaler_parsing():
    """test parsing of netscaler logs (which use extended W3C log format)"""

    file_ = "logs/netscaler.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["status"] == "302"
    assert hits[0]["userid"] is None
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "jsp"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == ""
    assert hits[0]["args"] == {"cvar": {1: ["HTTP-method", "GET"]}}
    assert hits[0]["generation_time_milli"] == 1000
    assert hits[0]["host"] == "foo"
    assert hits[0]["filename"] == "logs/netscaler.log"
    assert hits[0]["is_redirect"] is True
    assert hits[0]["date"] == datetime.datetime(2012, 8, 16, 11, 55, 13)
    assert hits[0]["lineno"] == 4
    assert hits[0]["ip"] == "172.20.1.0"
    assert hits[0]["query_string"] == ""
    assert hits[0]["path"] == "/Citrix/XenApp/Wan/auth/login.jsp"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/Citrix/XenApp/Wan/auth/login.jsp"
    assert (
        hits[0]["user_agent"] == "Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1;+Trident/4.0;+.NET+CLR+1.1.4322;"
        "+.NET+CLR+2.0.50727;+.NET+CLR+3.0.04506.648;+.NET+CLR+3.5.21022)"
    )


def test_shoutcast_parsing():
    """test parsing of shoutcast logs (which use extended W3C log format)"""

    file_ = "logs/shoutcast.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["status"] == "200"
    assert hits[0]["userid"] is None
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "/stream"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == ""
    assert hits[0]["args"] == {}
    assert hits[0]["generation_time_milli"] == 1000
    assert hits[0]["host"] == "foo"
    assert hits[0]["filename"] == "logs/shoutcast.log"
    assert hits[0]["is_redirect"] is False
    assert hits[0]["date"] == datetime.datetime(2015, 12, 7, 10, 37, 5)
    assert hits[0]["lineno"] == 3
    assert hits[0]["ip"] == "1.2.3.4"
    assert hits[0]["query_string"] == "title=UKR%20Nights"
    assert hits[0]["path"] == "/stream"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/stream?title=UKR%20Nights"
    assert hits[0]["user_agent"] == "NSPlayer/10.0.0.3702 WMFSDK/10.0"
    assert hits[0]["length"] == 65580


def test_splitted_date_and_time_parsing():
    """test parsing of logs with splitted date and time"""

    file_ = "logs/splitted_date_and_time.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["status"] == "200"
    assert hits[0]["userid"] is None
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "/stream"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == ""
    assert hits[0]["args"] == {}
    assert hits[0]["generation_time_milli"] == 1000
    assert hits[0]["host"] == "foo"
    assert hits[0]["filename"] == "logs/splitted_date_and_time.log"
    assert hits[0]["is_redirect"] is False
    assert hits[0]["date"] == datetime.datetime(2015, 12, 7, 10, 37, 5)
    assert hits[0]["lineno"] == 1
    assert hits[0]["ip"] == "1.2.3.4"
    assert hits[0]["query_string"] == "title=UKR%20Nights"
    assert hits[0]["path"] == "/stream"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/stream?title=UKR%20Nights"
    assert hits[0]["user_agent"] == "NSPlayer/10.0.0.3702 WMFSDK/10.0"
    assert hits[0]["length"] == 65580


def test_elb_parsing():
    """test parsing of elb logs"""

    file_ = "logs/elb.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert len(hits) == 1

    assert hits[0]["status"] == "200"
    assert hits[0]["userid"] is None
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "html"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == ""
    assert hits[0]["args"] == {}
    assert hits[0]["generation_time_milli"] == 1.048
    assert hits[0]["host"] == "foo"
    assert hits[0]["filename"] == "logs/elb.log"
    assert hits[0]["is_redirect"] is False
    assert hits[0]["date"] == datetime.datetime(2015, 0o5, 13, 23, 39, 43)
    assert hits[0]["lineno"] == 0
    assert hits[0]["ip"] == "1.2.3.4"
    assert hits[0]["query_string"] == ""
    assert hits[0]["path"] == "/path/index.html"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/path/index.html"
    assert (
        hits[0]["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko)"
        " Chrome/17.0.963.56 Safari/535.11"
    )
    assert hits[0]["length"] == 57


def test_alb_parsing():
    """test parsing of alb logs"""

    file_ = "logs/alb.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert len(hits) == 1

    assert hits[0]["status"] == "200"
    assert hits[0]["userid"] is None
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "html"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == ""
    assert hits[0]["args"] == {}
    assert hits[0]["generation_time_milli"] == 102
    assert hits[0]["host"] == "foo"
    assert hits[0]["filename"] == "logs/alb.log"
    assert hits[0]["is_redirect"] is False
    assert hits[0]["date"] == datetime.datetime(2020, 1, 1, 0, 55, 4)
    assert hits[0]["lineno"] == 0
    assert hits[0]["ip"] == "1.2.3.4"
    assert hits[0]["query_string"] == ""
    assert hits[0]["path"] == "/path/index.html"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/path/index.html"
    assert (
        hits[0]["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko)"
        " Chrome/17.0.963.56 Safari/535.11"
    )
    assert hits[0]["length"] == 24950


def test_amazon_cloudfront_web_parsing():
    """test parsing of amazon cloudfront logs (which use extended W3C log format)"""

    file_ = "logs/amazon_cloudfront_web.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["status"] == "200"
    assert hits[0]["userid"] is None
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "html"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == "https://example.com/"
    assert hits[0]["args"] == {"cvar": {1: ["HTTP-method", "GET"]}}
    assert hits[0]["generation_time_milli"] == 1.0
    assert hits[0]["host"] == "foo"
    assert hits[0]["filename"] == "logs/amazon_cloudfront_web.log"
    assert hits[0]["is_redirect"] is False
    assert hits[0]["date"] == datetime.datetime(2014, 5, 23, 1, 13, 11)
    assert hits[0]["lineno"] == 2
    assert hits[0]["ip"] == "192.0.2.10"
    assert hits[0]["query_string"] == ""
    assert hits[0]["path"] == "/view/my/file.html"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/view/my/file.html"
    assert (
        hits[0]["user_agent"]
        == "Mozilla/5.0 (Windows; U; Windows NT 6.1; de-DE) AppleWebKit/534.17 (KHTML, like Gecko)"
        " Chrome/10.0.649.0 Safari/534.17"
    )

    assert len(hits) == 1


def test_ovh_parsing():
    """test parsing of ovh logs (which needs to be forced, as it's not autodetected)"""

    file_ = "logs/ovh.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = import_logs.FORMATS["ovh"]
    import_logs.config.options.log_hostname = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["status"] == "301"
    assert hits[0]["userid"] == "theuser"
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "/"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == ""
    assert hits[0]["args"] == {"uid": "theuser"}
    assert hits[0]["generation_time_milli"] == 0
    assert hits[0]["host"] == "www.example.com"
    assert hits[0]["filename"] == "logs/ovh.log"
    assert hits[0]["is_redirect"] is True
    assert hits[0]["date"] == datetime.datetime(2012, 2, 10, 21, 42, 0o7)
    assert hits[0]["lineno"] == 0
    assert hits[0]["ip"] == "1.2.3.4"
    assert hits[0]["query_string"] == ""
    assert hits[0]["path"] == "/"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/"
    assert (
        hits[0]["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko)"
        " Chrome/17.0.963.56 Safari/535.11"
    )

    assert len(hits) == 1

    import_logs.config.options.log_hostname = "foo"


def test_gandi_parsing():
    """test parsing of gandi logs (which needs to be forced, as it's not autodetected)"""

    file_ = "logs/gandi.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = import_logs.FORMATS["gandi"]
    import_logs.config.options.log_hostname = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["status"] == "301"
    assert hits[0]["userid"] == "theuser"
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "/"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == ""
    assert hits[0]["args"] == {"cvar": {1: ["HTTP-method", "GET"]}, "uid": "theuser"}
    assert hits[0]["generation_time_milli"] == 0
    assert hits[0]["host"] == "www.example.com"
    assert hits[0]["filename"] == "logs/gandi.log"
    assert hits[0]["is_redirect"] is True
    assert hits[0]["date"] == datetime.datetime(2012, 2, 10, 21, 42, 0o7)
    assert hits[0]["lineno"] == 0
    assert hits[0]["ip"] == "1.2.3.4"
    assert hits[0]["query_string"] == ""
    assert hits[0]["path"] == "/"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/"
    assert (
        hits[0]["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko)"
        " Chrome/17.0.963.56 Safari/535.11"
    )

    assert hits[1]["status"] == "200"
    assert hits[1]["userid"] is None
    assert hits[1]["is_error"] is False
    assert hits[1]["extension"] == "/"
    assert hits[1]["is_download"] is False
    assert hits[1]["referrer"] == "https://www.example.com/"
    assert hits[0]["args"] == {"cvar": {1: ["HTTP-method", "GET"]}, "uid": "theuser"}
    assert hits[1]["length"] == 1124
    assert hits[1]["generation_time_milli"] == 0
    assert hits[1]["host"] == "www.example.com"
    assert hits[1]["filename"] == "logs/gandi.log"
    assert hits[1]["is_redirect"] is False
    assert hits[1]["date"] == datetime.datetime(2012, 2, 10, 21, 42, 0o7)
    assert hits[1]["lineno"] == 1
    assert hits[1]["ip"] == "125.125.125.125"
    assert hits[1]["query_string"] == ""
    assert hits[1]["path"] == "/"
    assert hits[1]["is_robot"] is False
    assert hits[1]["full_path"] == "/"
    assert hits[1]["user_agent"] == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:90.0) Gecko/20100101 Firefox/90.0"

    assert len(hits) == 2

    import_logs.config.options.log_hostname = "foo"


def test_incapsulaw3c_parsing():
    """test parsing of incapsula w3c logs (which needs to be forced, as it's not autodetected)"""

    file_ = "logs/incapsula_w3c.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = import_logs.FORMATS["incapsula_w3c"]
    import_logs.config.options.log_hostname = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["status"] == "200"
    assert hits[0]["userid"] is None
    assert hits[0]["is_error"] is False
    assert hits[0]["extension"] == "php"
    assert hits[0]["is_download"] is False
    assert hits[0]["referrer"] == ""
    assert hits[0]["args"] == {"cvar": {1: ["HTTP-method", '"GET"']}}
    assert hits[0]["length"] == 10117
    assert hits[0]["generation_time_milli"] == 0
    assert hits[0]["host"] == "www.example.com"
    assert hits[0]["filename"] == "logs/incapsula_w3c.log"
    assert hits[0]["is_redirect"] is False
    assert hits[0]["date"] == datetime.datetime(2017, 6, 28, 7, 26, 35)
    assert hits[0]["lineno"] == 0
    assert hits[0]["ip"] == "123.123.123.123"
    assert hits[0]["query_string"] == "variable=test"
    assert hits[0]["path"] == "/page.php"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/page.php"
    assert (
        hits[0]["user_agent"] == "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/58.0.3029.110 Safari/537.36"
    )

    assert hits[1]["status"] == "200"
    assert hits[1]["userid"] is None
    assert hits[1]["is_error"] is False
    assert hits[1]["extension"] == "/rss/news"
    assert hits[1]["is_download"] is False
    assert hits[1]["referrer"] == ""
    assert hits[0]["args"] == {"cvar": {1: ["HTTP-method", '"GET"']}}
    assert hits[1]["length"] == 0
    assert hits[1]["generation_time_milli"] == 0
    assert hits[1]["host"] == "www.example.com"
    assert hits[1]["filename"] == "logs/incapsula_w3c.log"
    assert hits[1]["is_redirect"] is False
    assert hits[1]["date"] == datetime.datetime(2017, 6, 26, 18, 21, 17)
    assert hits[1]["lineno"] == 1
    assert hits[1]["ip"] == "125.125.125.125"
    assert hits[1]["query_string"] == ""
    assert hits[1]["path"] == "/rss/news"
    assert hits[1]["is_robot"] is False
    assert hits[1]["full_path"] == "/rss/news"
    assert (
        hits[1]["user_agent"] == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:45.0) Gecko/20100101"
        " Thunderbird/45.8.0 Lightning/4.7.8"
    )

    assert len(hits) == 2


def test_amazon_cloudfront_rtmp_parsing():
    """test parsing of amazon cloudfront rtmp logs
    (which use extended W3C log format w/ custom fields for event info)"""

    file_ = "logs/amazon_cloudfront_rtmp.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.log_hostname = "foo"
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["is_download"] is False
    assert hits[0]["ip"] == "192.0.2.147"
    assert hits[0]["is_redirect"] is False
    assert hits[0]["filename"] == "logs/amazon_cloudfront_rtmp.log"
    assert hits[0]["event_category"] == "cloudfront_rtmp"
    assert hits[0]["event_action"] == "connect"
    assert hits[0]["lineno"] == 2
    assert hits[0]["status"] == "200"
    assert hits[0]["is_error"] is False
    assert hits[0]["event_name"] is None
    assert hits[0]["args"] == {}
    assert hits[0]["host"] == "foo"
    assert hits[0]["date"] == datetime.datetime(2010, 3, 12, 23, 51, 20)
    assert hits[0]["path"] == "/shqshne4jdp4b6.cloudfront.net/cfx/st\u200b"
    assert hits[0]["extension"] == "net/cfx/st\u200b"
    assert hits[0]["referrer"] == ""
    assert hits[0]["userid"] is None
    assert hits[0]["user_agent"] == "LNX 10,0,32,18"
    assert hits[0]["generation_time_milli"] == 0
    assert hits[0]["query_string"] == "key=value"
    assert hits[0]["is_robot"] is False
    assert hits[0]["full_path"] == "/shqshne4jdp4b6.cloudfront.net/cfx/st\u200b"

    assert hits[1]["is_download"] is False
    assert hits[1]["ip"] == "192.0.2.222"
    assert hits[1]["is_redirect"] is False
    assert hits[1]["filename"] == "logs/amazon_cloudfront_rtmp.log"
    assert hits[1]["event_category"] == "cloudfront_rtmp"
    assert hits[1]["event_action"] == "play"
    assert hits[1]["lineno"] == 3
    assert hits[1]["status"] == "200"
    assert hits[1]["is_error"] is False
    assert hits[1]["event_name"] == "myvideo"
    assert hits[1]["args"] == {}
    assert hits[1]["host"] == "foo"
    assert hits[1]["date"] == datetime.datetime(2010, 3, 12, 23, 51, 21)
    assert hits[1]["path"] == "/shqshne4jdp4b6.cloudfront.net/cfx/st\u200b"
    assert hits[1]["extension"] == "net/cfx/st\u200b"
    assert hits[1]["referrer"] == ""
    assert hits[1]["userid"] is None
    assert hits[1]["length"] == 3914
    assert hits[1]["user_agent"] == "LNX 10,0,32,18"
    assert hits[1]["generation_time_milli"] == 0
    assert hits[1]["query_string"] == "key=value"
    assert hits[1]["is_robot"] is False
    assert hits[1]["full_path"] == "/shqshne4jdp4b6.cloudfront.net/cfx/st\u200b"

    assert len(hits) == 2


def test_log_file_with_random_encoding():
    """Test that other file encoding work."""

    file_ = "logs/common_encoding_big5.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.debug = True
    import_logs.config.options.encoding = "big5"
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["path"] == "/為其兼行惡道"


def test_ignore_groups_option_removes_groups():
    """Test that the --ignore-groups option removes groups so they do not appear in hits."""

    file_ = "logs/iis.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = True
    import_logs.config.options.regex_groups_to_ignore = set(["userid", "generation_time_milli"])
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["userid"] is None
    assert hits[0]["generation_time_milli"] == 0


def test_regex_group_to_custom_var_options():
    """Test that the --regex-group-to-visit-cvar and
    --regex-group-to-page-cvar track regex groups to custom vars."""

    file_ = "logs/iis.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = True
    import_logs.config.options.regex_groups_to_ignore = set()
    import_logs.config.options.regex_group_to_visit_cvars_map = {
        "userid": "User Name",
        "date": "The Date",
    }
    import_logs.config.options.regex_group_to_page_cvars_map = {
        "generation_time_milli": "Generation Time",
        "referrer": "The Referrer",
    }
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert ["The Date", "2012-04-01 00:00:13"] in hits[0]["args"]["_cvar"].values()
    assert ["User Name", "theuser"] in hits[0]["args"]["_cvar"].values()
    assert ["Generation Time", "1687"] in hits[0]["args"]["cvar"].values()
    assert ["HTTP-method", "GET"] in hits[0]["args"]["cvar"].values()

    assert hits[0]["userid"] == "theuser"
    assert hits[0]["date"] == datetime.datetime(2012, 4, 1, 0, 0, 13)
    assert hits[0]["generation_time_milli"] == 1687
    assert hits[0]["referrer"] == ""


def test_w3c_custom_field_regex_option():
    """Test that --w3c-field-regex can be used to match custom W3C log fields."""

    file_ = "logs/iis.log"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = True
    import_logs.config.options.w3c_field_regexes = {
        "sc-substatus": r"(?P<substatus>\S+)",
        "sc-win32-status": r"(?P<win32_status>\S+)",
    }

    format = import_logs.W3cExtendedFormat()

    file_handle = open(file_)
    format.check_format(file_handle)
    match = None
    while not match:
        line = file_handle.readline()
        if not line:
            break
        match = format.match(line)
    file_handle.close()

    assert match is not None
    assert format.get("substatus") == "654"
    assert format.get("win32_status") == "456"


def test_custom_log_date_format_option():
    """Test that --log-date-format will change how dates are parsed in a custom log format."""

    file_ = "logs/custom_regex_custom_date.log"

    # have to override previous globals override for this test
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.options.w3c_field_regexes = None
    import_logs.config.options.regex_group_to_visit_cvars_map = None
    import_logs.config.options.regex_group_to_page_cvars_map = None
    import_logs.config.options.log_format_regex = (
        r"(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<date>.*?)\]\s+"
        r'"\S+\s+(?P<path>.*?)\s+\S+"\s+(?P<status>\S+)\s+(?P<length>\S+)'
    )
    import_logs.config.options.log_date_format = "%B - %d, %Y:%H:%M:%S"
    import_logs.config.format = import_logs.RegexFormat(
        "custom",
        import_logs.config.options.log_format_regex,
        import_logs.config.options.log_date_format,
    )

    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["date"] == datetime.datetime(2012, 2, 10, 16, 42, 7)


def test_static_ignores():
    """Test static files are ignored."""
    file_ = "logs/static_ignores.log"

    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.config.format = None
    import_logs.config.options.enable_static = False
    # ensure robots.txt would be imported if not detected as static
    import_logs.config.options.download_extensions = "txt,doc"
    import_logs.config.options.enable_http_redirects = True
    import_logs.config.options.enable_http_errors = True
    import_logs.config.options.replay_tracking = False
    import_logs.config.options.w3c_time_taken_in_millisecs = False
    import_logs.parser.parse(file_)

    hits = [hit.args for hit in import_logs.Recorder.recorders]

    assert len(hits) == 1


def test_glob_filenames():
    """Test globbing of filenames"""
    argv = ["--url=http://localhost", "logs/common*.log", "logs/elb.log"]

    config = import_logs.Configuration(argv)

    assert config.filenames == [
        "logs/common.log",
        "logs/common_complete.log",
        "logs/common_encoding_big5.log",
        "logs/common_vhost.log",
        "logs/elb.log",
    ]


# UrlHelper tests
def test_urlhelper_convert_array_args():
    def _test(input, expected):
        actual = import_logs.UrlHelper.convert_array_args(input)
        assert json.loads(json.dumps(actual)) == json.loads(json.dumps(expected))

    # without array args
    _test({"abc": "def", "ghi": 23}, {"abc": "def", "ghi": 23})

    # with normal array args
    _test({"abc[]": "def", "ghi": 23}, {"abc": ["def"], "ghi": 23})

    # with associative array args
    _test(
        {"abc[key1]": "def", "ghi[0]": 23, "abc[key2]": "val2", "abc[key3][key4]": "val3"},
        {"abc": {"key1": "def", "key2": "val2", "key3": {"key4": "val3"}}, "ghi": [23]},
    )

    # with array index keys
    _test(
        {"abc[0]": 1, "abc[2]": 2, "abc[1]": 3, "ghi[0]": 4, "ghi[2]": 5},
        {"abc": [1, 3, 2], "ghi": {"0": 4, "2": 5}},
    )

    # with both associative & normal arrays
    _test(
        {"abc[key1][0]": "def", "abc[key1][1]": "ghi", "abc[key2][4]": "hij"},
        {"abc": {"key1": ["def", "ghi"], "key2": {4: "hij"}}},
    )

    # with multiple inconsistent data strucutres
    # using OrderedDict to make the test deterministic
    inputdata = OrderedDict([("abc[key1][3]", 1), ("abc[key1][]", 23), ("ghi[key2][]", 45), ("ghi[key2][abc]", 56)])
    _test(inputdata, {"abc": {"key1": [23]}, "ghi": {"key2": {"abc": 56}}})


# TimeHelper tests
def test_timedelta_from_timezone():
    def _test(input, expected):
        delta = import_logs.TimeHelper.timedelta_from_timezone(input)
        assert delta == datetime.timedelta(0, expected)

    _test("+0200", 7200)
    _test("+1400", 50400)
    _test("+0045", 2700)
    _test("+0330", 12600)
    _test("+0000", 0)
    _test("-0500", -18000)
    _test("-1200", -43200)
    _test("-0040", -2400)
    _test("-0230", -9000)
    _test("-0000", 0)


# Piwik error test
def test_piwik_error_construct():
    """Test that Piwik exception can be created."""

    try:
        raise import_logs.PiwikHttpBase.Error("test message", 120)
    except import_logs.PiwikHttpBase.Error as e:
        assert e.code == 120
        assert e.args[0] == "test message"


def test_gz_parsing():
    """test parsing of gz compressed file"""

    file_ = "logs/common.log.gz"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["ip"] == "1.2.3.5"
    assert hits[0]["path"] == "/form"
    assert hits[0]["status"] == "200"
    assert hits[0]["length"] == 145
    assert hits[0]["userid"] == "admin"


def test_bz2_parsing():
    """test parsing of bz2 compressed file"""

    file_ = "logs/common.log.bz2"

    # have to override previous globals override for this test
    import_logs.config.options.custom_w3c_fields = {}
    Recorder.recorders = []
    import_logs.parser = import_logs.Parser()
    import_logs.parser.parse(file_)

    hits = [hit.__dict__ for hit in Recorder.recorders]

    assert hits[0]["ip"] == "1.2.3.7"
    assert hits[0]["path"] == "/"
    assert hits[0]["status"] == "200"
    assert hits[0]["length"] == 444
    assert hits[0]["userid"] == "theboss"


def test_static_resolver_with_idsite():
    with _import_logs_config(_mock_config(replay_tracking=True)):
        import_logs.piwik = Piwik()
        import_logs.stats = import_logs.Statistics()
        import_logs.resolver = import_logs.StaticResolver("194edb22-394a-48e5-aed8-0797ab29d2ae")

        assert "194edb22-394a-48e5-aed8-0797ab29d2ae" in import_logs.stats.piwik_sites


# ---------------------------------------------------------------------------
# Helpers for OAuth / rate-limit tests
# ---------------------------------------------------------------------------


def _make_http_error(code, headers=None):
    """Build a urllib.error.HTTPError with the given status code and optional headers."""
    e = urllib.error.HTTPError(url="http://example.com", code=code, msg="", hdrs=None, fp=io.BytesIO(b""))
    e.code = code
    if headers is not None:
        e.headers = headers
    return e


def _make_piwik_http():
    """Return a fresh PiwikHttpUrllib with shared rate-limit state reset."""
    import_logs.PiwikHttpUrllib._rate_limit_until = 0.0
    return import_logs.PiwikHttpUrllib()


def _mock_config(delay_after_failure=0, max_attempts=3, replay_tracking=False):
    """Return a MagicMock that satisfies config.options accesses in _call_wrapper."""
    cfg = MagicMock()
    cfg.options.delay_after_failure = delay_after_failure
    cfg.options.max_attempts = max_attempts
    cfg.options.replay_tracking = replay_tracking
    return cfg


def _set_config(new_config):
    """Set import_logs.config, returning (had_config, old_config) for restore."""
    had = hasattr(import_logs, "config")
    old = getattr(import_logs, "config", None)
    import_logs.config = new_config
    return had, old


def _restore_config(had, old):
    if had:
        import_logs.config = old
    elif hasattr(import_logs, "config"):
        delattr(import_logs, "config")


@contextmanager
def _import_logs_config(cfg, reset_rate_limit_after=False):
    """Temporarily set ``import_logs.config``; optionally reset shared 429 clock after."""
    had, old = _set_config(cfg)
    try:
        yield
    finally:
        _restore_config(had, old)
        if reset_rate_limit_after:
            import_logs.PiwikHttpUrllib._rate_limit_until = 0.0


def _rate_limit_test_config(delay_after_failure, max_attempts=3):
    """Mock ``config`` for 429 tests; resets shared rate-limit deadline after."""
    return _import_logs_config(
        _mock_config(delay_after_failure=delay_after_failure, max_attempts=max_attempts),
        reset_rate_limit_after=True,
    )


# ---------------------------------------------------------------------------
# OAuth refresh and HTTP 429 handling
# ---------------------------------------------------------------------------


def test_init_token_auth_no_concurrent_fetches():
    """Two threads calling init_token_auth() concurrently must not fetch in parallel —
    the lock should serialize them so at most one fetch is in-flight at a time."""
    concurrent_count = [0]
    max_concurrent = [0]

    def slow_get_token(self):
        concurrent_count[0] += 1
        max_concurrent[0] = max(max_concurrent[0], concurrent_count[0])
        time.sleep(0.05)  # simulate network latency
        concurrent_count[0] -= 1
        return {"token_type": "Bearer", "access_token": "tok"}

    with _import_logs_config(_mock_config()):
        with patch.object(import_logs.Configuration, "_get_token_auth", slow_get_token):
            cfg = import_logs.Configuration.__new__(import_logs.Configuration)
            cfg.piwik_token = None
            t1 = threading.Thread(target=cfg.init_token_auth)
            t2 = threading.Thread(target=cfg.init_token_auth)
            t1.start()
            t2.start()
            t1.join()
            t2.join()

        assert max_concurrent[0] == 1, "Fetches must not overlap — max concurrent was %d" % max_concurrent[0]
        assert cfg.piwik_token is not None


def test_call_authentication_wrapper_retries_on_401_when_token_refreshed():
    """On 401, wrapper refreshes token and retries the call."""
    piwik = _make_piwik_http()
    call_count = [0]

    def func():
        call_count[0] += 1
        if call_count[0] == 1:
            raise _make_http_error(401)
        return "ok"

    cfg = _mock_config()
    cfg.piwik_token = "old-token"

    def refresh():
        cfg.piwik_token = "new-token"

    cfg.init_token_auth = refresh

    with _import_logs_config(cfg):
        result = piwik._call_authentication_wrapper(func)
        assert result == "ok"
        assert call_count[0] == 2


def test_call_authentication_wrapper_raises_when_token_unchanged_after_refresh():
    """If the token did not change after refresh (e.g. refresh also failed), re-raise 401."""
    piwik = _make_piwik_http()

    def func():
        raise _make_http_error(401)

    cfg = _mock_config()
    cfg.piwik_token = "same-token"
    cfg.init_token_auth = lambda: None  # no-op — token stays the same

    with _import_logs_config(cfg):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            piwik._call_authentication_wrapper(func)
        assert exc_info.value.code == 401


def test_call_wrapper_respects_retry_after_header():
    """429 with numeric Retry-After sets _rate_limit_until to now + header value."""
    piwik = _make_piwik_http()
    call_count = [0]

    def func(*a, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            raise _make_http_error(429, headers={"Retry-After": "30"})
        return "ok"

    with _rate_limit_test_config(10), patch("piwik_pro_log_analytics.import_logs.time") as mock_time:
        mock_time.time.side_effect = [0.0, 0.0, 0.0, 31.0]
        mock_time.sleep = MagicMock()
        result = piwik._call_wrapper(func, None, None)

        assert result == "ok"
        assert call_count[0] == 2
        assert import_logs.PiwikHttpUrllib._rate_limit_until == pytest.approx(30.0, abs=0.1)
        mock_time.sleep.assert_called_once()
        sleep_arg = mock_time.sleep.call_args[0][0]
        assert sleep_arg == pytest.approx(30.0, abs=3.5)  # 30 + up to 10% jitter


def test_call_wrapper_falls_back_to_default_delay_without_retry_after():
    """429 without Retry-After header uses delay_after_failure as the wait."""
    piwik = _make_piwik_http()
    call_count = [0]

    def func(*a, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            raise _make_http_error(429)
        return "ok"

    with _rate_limit_test_config(7), patch("piwik_pro_log_analytics.import_logs.time") as mock_time:
        mock_time.time.side_effect = [0.0, 0.0, 0.0, 8.0]
        mock_time.sleep = MagicMock()
        result = piwik._call_wrapper(func, None, None)

        assert result == "ok"
        assert import_logs.PiwikHttpUrllib._rate_limit_until == pytest.approx(7.0, abs=0.1)
        sleep_arg = mock_time.sleep.call_args[0][0]
        assert sleep_arg == pytest.approx(7.0, abs=0.8)  # 7 + up to 10% jitter


def test_call_wrapper_logs_debug_on_malformed_retry_after(caplog):
    """Non-numeric Retry-After (e.g. HTTP-date) logs debug and falls back to default delay."""
    piwik = _make_piwik_http()
    call_count = [0]

    def func(*a, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            raise _make_http_error(429, headers={"Retry-After": "Wed, 21 Oct 2025 07:28:00 GMT"})
        return "ok"

    with (
        _rate_limit_test_config(5),
        caplog.at_level(logging.DEBUG),
        patch("piwik_pro_log_analytics.import_logs.time") as mock_time,
    ):
        mock_time.time.side_effect = [0.0, 0.0, 0.0, 6.0]
        mock_time.sleep = MagicMock()
        result = piwik._call_wrapper(func, None, None)

        assert result == "ok"
        assert any("Retry-After" in r.message for r in caplog.records)
        assert import_logs.PiwikHttpUrllib._rate_limit_until == pytest.approx(5.0, abs=0.1)


def test_call_wrapper_429_counts_against_max_attempts():
    """429 responses exhaust max_attempts and raise PiwikHttpBase.Error."""
    piwik = _make_piwik_http()

    def func(*a, **kw):
        raise _make_http_error(429)

    with _rate_limit_test_config(0), patch("piwik_pro_log_analytics.import_logs.time") as mock_time:
        mock_time.time.return_value = 0.0
        mock_time.sleep = MagicMock()
        with pytest.raises(import_logs.PiwikHttpBase.Error) as exc_info:
            piwik._call_wrapper(func, None, None)
    assert exc_info.value.code == 429


def test_rate_limit_shared_across_workers():
    """A rate-limit window set by one worker causes other workers to wait."""
    piwik = _make_piwik_http()
    import_logs.PiwikHttpUrllib._rate_limit_until = 100.0

    def func(*a, **kw):
        return "ok"

    with _rate_limit_test_config(1), patch("piwik_pro_log_analytics.import_logs.time") as mock_time:
        sleep_calls = []
        mock_time.time.side_effect = [0.0, 101.0]
        mock_time.sleep = lambda n: sleep_calls.append(n)
        result = piwik._call_wrapper(func, None, None)

    assert result == "ok"
    assert len(sleep_calls) == 1, "Worker should have slept once for the rate-limit window"
    assert sleep_calls[0] == pytest.approx(100.0, abs=11.0)  # 100 + up to 10% jitter


def test_rate_limit_until_extended_mid_sleep_is_respected():
    """If _rate_limit_until is extended while a worker sleeps, the worker re-checks
    and sleeps again for the remainder."""
    piwik = _make_piwik_http()
    import_logs.PiwikHttpUrllib._rate_limit_until = 5.0

    sleep_calls = []

    def extending_sleep(n):
        sleep_calls.append(n)
        if len(sleep_calls) == 1:
            # Another worker extends the deadline while this worker sleeps
            import_logs.PiwikHttpUrllib._rate_limit_until = 10.0

    def func(*a, **kw):
        return "ok"

    with _rate_limit_test_config(1), patch("piwik_pro_log_analytics.import_logs.time") as mock_time:
        mock_time.time.side_effect = [0.0, 0.0, 11.0]
        mock_time.sleep = extending_sleep
        result = piwik._call_wrapper(func, None, None)

    assert result == "ok"
    assert len(sleep_calls) == 2, "Worker should sleep twice: once for original window, once after extension"


def test_redact_sensitive_for_log_masks_token_dict():
    redacted = import_logs._redact_sensitive_for_log(
        {
            "access_token": "eyJhbGciOiJSUzI1NiJ9.secret",
            "token_type": "Bearer",
            "expires_in": 1800,
        }
    )
    assert redacted == {
        "access_token": "[***REDACTED***]",
        "token_type": "Bearer",
        "expires_in": 1800,
    }


def test_redact_sensitive_for_log_masks_authorization_header():
    redacted = import_logs._redact_sensitive_for_log(
        {
            "Content-type": "application/json",
            "Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.secret",
        }
    )
    assert redacted["Authorization"] == "[***REDACTED***]"
    assert redacted["Content-type"] == "application/json"


def test_redact_sensitive_for_log_masks_json_body_bytes():
    payload = json.dumps(
        {
            "grant_type": "client_credentials",
            "client_id": "app-id",
            "client_secret": "super-secret",
        }
    ).encode("utf-8")
    redacted = import_logs._redact_sensitive_for_log(payload)
    assert isinstance(redacted, str)
    parsed = json.loads(redacted)
    assert parsed["client_secret"] == "[***REDACTED***]"
    assert parsed["client_id"] == "app-id"
    assert "super-secret" not in redacted


def test_redact_sensitive_for_log_masks_json_response_string():
    response = '{"access_token":"eyJ.secret","token_type":"Bearer","expires_in":1800}'
    redacted = import_logs._redact_sensitive_for_log(response)
    assert "eyJ.secret" not in redacted
    assert (
        '"access_token": "[***REDACTED***]"' in redacted
        or '"access_token":"[***REDACTED***]"' in redacted
    )


def test_redact_sensitive_for_log_fails_closed_on_non_json_string():
    assert (
        import_logs._redact_sensitive_for_log("not-json client_secret=leak")
        == "[***REDACTED***]"
    )


def test_redact_sensitive_for_log_fails_closed_on_undecodable_bytes():
    assert import_logs._redact_sensitive_for_log(b"\xff\xfe secret") == "[***REDACTED***]"

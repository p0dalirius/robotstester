#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          :
# Author             :
# Date created       :
# Date last modified :
# Python Version     : 3.*

from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from rich.console import Console
from rich import box
from rich.table import Table
import argparse
import json
import re
import requests
import sys

banner = "[~] Robots.txt tester, v1.0\n"

class Logger(object):
    def __init__(self, verbosity=0, quiet=False):
        self.verbosity = verbosity
        self.quiet = quiet

    def debug(self, message):
        if self.verbosity >= 2:
            console.print("{}[DEBUG]{} {}".format("[yellow3]", "[/yellow3]", message), highlight=False)

    def verbose(self, message):
        if self.verbosity >= 1:
            console.print("{}[VERBOSE]{} {}".format("[blue]", "[/blue]", message), highlight=False)

    def info(self, message):
        if not self.quiet:
            console.print("{}[*]{} {}".format("[bold blue]", "[/bold blue]", message), highlight=False)

    def success(self, message):
        if not self.quiet:
            console.print("{}[+]{} {}".format("[bold green]", "[/bold green]", message), highlight=False)

    def warning(self, message):
        if not self.quiet:
            console.print("{}[-]{} {}".format("[bold orange3]", "[/bold orange3]", message), highlight=False)

    def error(self, message):
        if not self.quiet:
            console.print("{}[!]{} {}".format("[bold red]", "[/bold red]", message), highlight=False)

class RobotsParser(object):
    def __init__(self, robots_url, logger):
        super(RobotsParser, self).__init__()
        self.logger = logger
        if not robots_url.endswith("/robots.txt"):
            robots_url += "/robots.txt"
        self.robots_url = robots_url
        self.base_url = self.robots_url.split('/robots.txt')[0]
        self.urls = []
        try:
            self.r = requests.get(robots_url)
        except Exception as e:
            self.logger.debug(e)
            self.r = None

    def parse(self):
        self.urls = []
        if self.r is not None:
            if self.r.status_code == 200:
                entries = re.findall("(Allow|Disallow)[ ]*:(.*)", self.r.content.decode('UTF-8'))
                sanitized = []
                for e in entries:
                    robots_entry = ''.join(e)
                    url = e[1].strip()
                    if url.endswith('?') : url = url[:-1]
                    if url.endswith('$') : url = url[:-1]
                    sanitized.append({"robots_entry":robots_entry, "url":url})
                for s in sanitized:
                    if "*" in s["url"]:
                        dirs = s["url"].split('/')
                        wildcard_index = [k for k in range(len(dirs)) if '*' in dirs[k]][0]
                        s["url"] = '/'.join(s["url"].split('/')[:wildcard_index])
                    self.urls.append(self.base_url + s["url"])
            self.urls = list(set(self.urls))
        return self.urls

    def __repr__(self):
        return "<RobotsParser url='%s'>" % self.url

def get_options():
    description = "This Python script can enumerate all URLs present in robots.txt files, and test whether they can be accessed or not."

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-u",
        "--url",
        dest="url",
        action="store",
        default=0,
        help="URL to the robots.txt to test e.g. https://example.com:port/path",
    )
    group.add_argument(
        "-f",
        "--urlsfile",
        dest="urlsfile",
        action="store",
        default=None,
        required=False,
        help="List of robots.txt urls to test",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="count",
        default=0,
        help="verbosity level (-v for verbose, -vv for debug)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Show no information at all",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        dest="verify",
        action="store_false",
        default=True,
        required=False,
        help="Allow insecure server connections when using SSL (default: False)",
    )
    parser.add_argument(
        "-L",
        "--location",
        dest="redirect",
        action="store_true",
        default=False,
        required=False,
        help="Follow redirects (default: False)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        action="store",
        type=int,
        default=5,
        required=False,
        help="Number of threads (default: 5)",
    )
    parser.add_argument(
        "-j",
        "--jsonfile",
        dest="jsonfile",
        default=None,
        required=False,
        help="Save results to specified JSON file.",
    )
    parser.add_argument(
        '-x',
        '--proxy',
        action="store",
        default=None,
        dest='proxy',
        help="Specify a proxy to use for requests (e.g., http://localhost:8080)"
    )
    parser.add_argument(
        '-b', '--cookies',
        action="store",
        default=None,
        dest='cookies',
        help='Specify cookies to use in requests. (e.g., --cookies "cookie1=blah;cookie2=blah")'
    )
    options = parser.parse_args()
    return options

def test_url(options, url, proxies, cookies, results):
    try:
        r = requests.get(
            url=url,
            verify=options.verify, # this is to set the client to accept insecure servers
            proxies=proxies,
            cookies=cookies,
            allow_redirects=options.redirect,
            stream=True # this is to prevent the download of huge files, focus on the request, not on the data
        )
    except requests.exceptions.ProxyError:
        logger.error("Invalid proxy specified")
        raise SystemExit
    logger.debug(f"Obtained results: {url}, {str(r.status_code)}, {str(len(r.text))}, {r.reason}")
    results[url] = {"status_code": r.status_code, "length": len(r.text), "reason": r.reason[:100]}

def print_results(console, results):
    logger.verbose("Parsing & printing results")
    table = Table(show_header=True, header_style="bold blue", border_style="blue", box=box.SIMPLE)
    table.add_column("URL")
    table.add_column("Length")
    table.add_column("Status code")
    table.add_column("Reason")
    for result in results.items():
        if result[1]["status_code"] == 200:  # This means the method is accepted
            style = "green"
        elif (300 <= result[1]["status_code"] <= 399):
            style = "cyan"
        elif 400 <= result[1]["status_code"] <= 499:  # This means the method is disabled in most cases
            style = "red"
        elif (500 <= result[1]["status_code"] <= 599) and result[1][
            "status_code"] != 502:  # This means the method is not implemented in most cases
            style = "orange3"
        elif result[1]["status_code"] == 502:  # This probably means the method is accepted but request was malformed
            style = "yellow4"
        else:
            style = None
        table.add_row(result[0], str(result[1]["length"]), str(result[1]["status_code"]), result[1]["reason"], style=style)
    console.print(table)

def json_export(results, json_file):
    f = open(json_file, "w")
    f.write(json.dumps(results, indent=4) + "\n")
    f.close()

def main(options, logger, console):
    logger.info("Enumerating URLs from robots.txt")
    results = {}
    # Verifying the proxy option
    if options.proxy:
        try:
            proxies = {
                "http": "http://" + options.proxy.split('//')[1],
                 "https": "http://" + options.proxy.split('//')[1]
            }
            logger.debug(f"Setting proxies to {str(proxies)}")
        except (IndexError, ValueError):
            logger.error("Invalid proxy specified ")
            sys.exit(1)
    else:
        logger.debug("Setting proxies to 'None'")
        proxies = None
    # Parsing cookie option
    if options.cookies:
        cookie = SimpleCookie()
        cookie.load(options.cookies)
        cookies = {key: value.value for key, value in cookie.items()}
    else:
        cookies = {}

    found_urls = []
    if options.urlsfile is not None:
        if os.path.exists(options.urlsfile):
            f = open(options.urlsfile,'r')
            list_of_urls = [l.strip() for l in f.readlines()]
            f.close()
            for url in list_of_urls:
                found_urls += RobotsParser(url, logger).parse()
        else:
            logger.warning("The specified urlfile does not exists or is not readable.")
    elif options.url is not None:
        if not (options.url.startswith('http://') or options.url.startswith('https://')):
            options.url = "http://" + options.url
        found_urls = RobotsParser(options.url, logger).parse()
    else:
        logger.warning("No URL was given")
    found_urls = sorted(list(set(found_urls)))

    logger.info("Found %d URLs to test in robots.txt" % len(found_urls))
    logger.debug(found_urls)

    if len(found_urls) > 0:
        # Waits for all the threads to be completed
        with ThreadPoolExecutor(max_workers=min(options.threads, len(found_urls))) as tp:
            for url in found_urls:
                tp.submit(test_url, options, url, proxies, cookies, results)

        # Sorting the results by url
        results = {key: results[key] for key in sorted(results)}

        # Parsing and print results
        print_results(console, results)

        # Export to JSON if specified
        if options.jsonfile is not None:
            json_export(results, options.jsonfile)

if __name__ == '__main__':
    try:
        print(banner)
        options = get_options()
        logger = Logger(options.verbosity, options.quiet)
        console = Console()
        if not options.verify:
            # Disable warings of insecure connection for invalid cerificates
            requests.packages.urllib3.disable_warnings()
            # Allow use of deprecated and weak cipher methods
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
            try:
                requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
            except AttributeError:
                pass
        main(options, logger, console)
    except KeyboardInterrupt:
        logger.info("Terminating script ...")
        raise SystemExit

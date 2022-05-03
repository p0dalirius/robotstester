# Robots.txt tester

<p align="center">
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/robotstester">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
  <br>
</p>

With this script, you can enumerate all URLs present in robots.txt files, and test whether you can access them or not.

![example](assets/example.gif)

## Setup

Clone the repository and install the dependencies :

```sh
git clone https://github.com/p0dalirius/robotstester
cd robotstester
python3 setup.py install
```

## Usage

```sh
robotstester -u http://www.example.com/
```

You can find here a complete list of options :

```
[~] Robots.txt tester, v1.2.0

usage: robotstester.py [-h] (-u URL | -f URLSFILE) [-v] [-q] [-k] [-L] [-t THREADS] [-p] [-j JSONFILE] [-x PROXY] [-b COOKIES]

This Python script can enumerate all URLs present in robots.txt files, and test whether they can be accessed or not.

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL to the robots.txt to test e.g. https://example.com:port/path
  -f URLSFILE, --urlsfile URLSFILE
                        List of robots.txt urls to test
  -v, --verbose         verbosity level (-v for verbose, -vv for debug)
  -q, --quiet           Show no information at all
  -k, --insecure        Allow insecure server connections when using SSL (default: False)
  -L, --location        Follow redirects (default: False)
  -t THREADS, --threads THREADS
                        Number of threads (default: 5)
  -p, --parsable        Parsable output
  -j JSONFILE, --jsonfile JSONFILE
                        Save results to specified JSON file.
  -x PROXY, --proxy PROXY
                        Specify a proxy to use for requests (e.g., http://localhost:8080)
  -b COOKIES, --cookies COOKIES
                        Specify cookies to use in requests. (e.g., --cookies "cookie1=blah;cookie2=blah")
```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

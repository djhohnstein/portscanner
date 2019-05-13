# portscanner

Portscanner is a portscanner, written in golang! Minor speed hits for prettier output and file writing.

## Usage

```
Usage of portscanner:
  -hosts string
        Comma separated list of hostnames/ips/cidrs to scan.
  -outfile string
        Optional: Destination to store results.
  -ports string
        Ports to scan on the remote hosts. Defaults to top 1000 ports.
  -timeout int
        Timeout in milliseconds. (default 500)
```

## Example

```
#> portscanner -ports 80,443 -hosts uber.com -outfile web.txt

Scan results for 104.36.196.219 (uber.com):
        443   open
        80    open

[*] Wrote results to test.txt
#> cat web.txt
104.36.196.219 (uber.com)                            (443/open, 80/open)
```

## Support

This project is released as-is and will not be supported. Any and all issues will be closed.
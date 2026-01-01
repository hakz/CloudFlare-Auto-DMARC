# CloudFlare-Auto-DMARC
Quickly check and update your DMARC and SPF records on thousands of parked domains.

```bash
python3 cloudflare-auto-dmarc.py --help

    ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ███████╗██╗      █████╗ ██████╗ ███████╗
    ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝
    ██║     ██║     ██║   ██║██║   ██║██║  ██║█████╗  ██║     ███████║██████╔╝█████╗
    ██║     ██║     ██║   ██║██║   ██║██║  ██║██╔══╝  ██║     ██╔══██║██╔══██╗██╔══╝
    ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝██║     ███████╗██║  ██║██║  ██║███████╗
    ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    █████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ███╗   ███╗ █████╗ ██████╗  ██████╗
    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗████╗ ████║██╔══██╗██╔══██╗██╔════╝
    ███████║██║   ██║   ██║   ██║   ██║    ██║  ██║██╔████╔██║███████║██████╔╝██║
    ██╔══██║██║   ██║   ██║   ██║   ██║    ██║  ██║██║╚██╔╝██║██╔══██║██╔══██╗██║
    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██████╔╝██║ ╚═╝ ██║██║  ██║██║  ██║╚██████╗
    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝

Usage:  cloudflare-auto-dmarc.py [-a | -h | -v] [-e VARIABLE] [-t TOKEN] [-o FILE]
-a, --autofix

    Auto-secure DMARC records after the audit.

-e VARIABLE, --env=VARIABLE

    The environmental variable where you've stored your CloudFlare API Token.
    Don't forget to run 'export KEY=VALUE'!

-h, --help

    Get this help message.

-t TOKEN, --token=TOKEN

    Pass your CloudFlare API token as an argument before running

-o FILE, --output=FILE

    This is where you will save your CSV report.
```
-v, --vulnerable-only

    Output file will only include vulnerable domains in the results

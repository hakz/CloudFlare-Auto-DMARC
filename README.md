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

# CloudFlare Auto DMARC
Quickly check and update your DMARC and SPF records on thousands of parked domains.

## Quickstart

1. [Create a DNS read/write Cloudflare token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
   
3. Add your token as an environmental variable in your terminal:
   
    ```bash
    export CF_API_TOKEN=<token_goes_here>`
    ```
    
4. Run the script in a read-only mode to audit your domains' security:
   
    ```bash
    python3 cloudflare-auto-dmarc.py -e CF_API_TOKEN -o dmarc.csv
    ```

## Flags
You can request a copy of the man page.
```
python3 cloudflare-auto-dmarc.py --help
```
Which will result in the following:
```bash
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

-v, --vulnerable-only

    Output file will only include vulnerable domains in the results
```

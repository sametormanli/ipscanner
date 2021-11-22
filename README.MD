
# IP Scanner

IP scanner tool with build-in python libraries. Currently works only Linux based systems.

## Usage

```bash
  python ipscanner.py [option] [argument]
```
## Options
**-i** | Interface scan: Without argument, select interface from list.

_Examples:_

```bash
  python ipscanner.py -i
  python ipscanner.py -i eth0
  python ipscanner.py -i bond2
```
**-r** | IP range scan.

_Examples:_

```bash
  python ipscanner.py -r startIP-endIP
  python ipscanner.py -r 192.168.1.192-192.168.1.255
```
**-n** | Inventory scan: Only accepts .csv reports. ```report.csv``` is a sample report.

_Examples:_

```bash
  python ipscanner.py -n report.csv
```
## Features

#### Scan mode 
Determines how long to wait the ping response. Normal mode waits a single response fast mode waits 1s and ultra mode waits 200ms. On stable and fast networks average ping response is less then 50ms.

#### Print process
Prints the ping processes during the scan.

#### Export result
Exports the scan result under home directory. 

Full path -> ```~/ipscanner/```
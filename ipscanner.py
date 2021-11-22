import subprocess
import ipaddress
import datetime
import sys
import re
import os


class IPScanner:
    def __init__(self):
        self.inv_title = []
        self.inventory = {}
        self.ip_list = {}
        self.interfaces = {}
        self.mode = ''
        self.start_time = None
        self.end_time = None

    def main(self, arguments):
        if len(arguments) == 1:
            self.usage()
        elif len(arguments) == 2:
            if arguments[1] == '-i':
                self.collect_int()
                self.scan_int(self.select_int())
            else:
                print('Invalid option.')
                self.usage()
        elif len(arguments) == 3:
            if arguments[1] == '-r':
                try:
                    s, e = arguments[2].split('-')
                    if self.ip_validate(s) and self.ip_validate(e):
                        if ipaddress.IPv4Address(s) < ipaddress.IPv4Address(e):
                            self.collect_range(s, e)
                            self.range_scan(s, e, False)
                        else:
                            print('EndIP must be greater than startIP.')
                    else:
                        print('Enter valid IPs.')
                        exit()
                except ValueError:
                    print('Invalid IP range format. Format: startIP-endIP')
                    exit()
            elif arguments[1] == '-i':
                self.collect_int()
                if arguments[2] in self.interfaces:
                    self.scan_int(self.interfaces[arguments[2]])
                else:
                    print('Invalid interface.')
                    self.usage()
            elif arguments[1] == '-n':
                try:
                    self.read_inventory(arguments[2])
                    self.scan_inventory()
                except FileNotFoundError:
                    print('Please add inventory as .csv file.')
                    exit()
        else:
            print('Invalid usage.')
            self.usage()

    # Range

    def collect_range(self, start, end):
        s, e = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
        while s <= e:
            self.ip_list[str(s)] = 'Pinging...'
            s += 1

    def range_scan(self, start, end, interface):
        self.mode = f'i {interface}' if interface else f'r {start} {end}'
        fast, pro, out = self.options()
        self.start_time = datetime.datetime.now()
        for ip in self.ip_list:
            self.ip_list[ip] = self.ping(ip, fast, not pro)
        self.end_time = datetime.datetime.now()
        self.print_range(out)

    # Interface

    def collect_int(self):
        ip = subprocess.Popen(['ip', 'a'], stdout=subprocess.PIPE)
        grep = subprocess.run(['grep', 'inet'], stdin=ip.stdout, capture_output=True)
        interfaces = grep.stdout.decode('utf-8').split('\n')
        for interface in interfaces:
            if 'inet ' in interface:
                spl = interface.strip().split()
                self.interfaces[spl[-1]] = spl[1]

    def select_int(self):
        print('\nInterfaces',
              '\n----------')
        for key, val in self.interfaces.items():
            print(f'{key}: {val}')
        while True:
            name = input('\nSelect the interface: ')
            if name == '':
                exit()
            elif name not in self.interfaces:
                print('Invalid entry! Try again or hit enter to exit.')
                continue
            return self.interfaces[name]

    def scan_int(self, name):
        network = ipaddress.ip_network(name, False).hosts()
        for ip in network:
            self.ip_list[str(ip)] = 'Pinging...'
        self.range_scan(list(self.ip_list)[0], list(self.ip_list)[-1], name)

    # Inventory

    def read_inventory(self, filename):
        self.mode = filename
        with open(filename, 'r') as file:
            self.inv_title = [*file.readline().split(','), 'Ping Result']
            self.inv_title[-2] = self.inv_title[-2].strip('\n')
            for line in file:
                lst = line.strip('\n').split(',')
                self.inventory[lst[0]] = {
                    'type': lst[1],
                    'ip': lst[2],
                    'ping': 'Pinging...'
                }

    def scan_inventory(self):
        fast, pro, out = self.options()
        self.start_time = datetime.datetime.now()
        for key, val in self.inventory.items():
            if self.ip_validate(val['ip']):
                self.inventory[key]['ping'] = self.ping(val['ip'], fast, not pro)
            else:
                self.inventory[key]['ping'] = 'Invalid IP.'
        self.end_time = datetime.datetime.now()
        self.print_report()
        if out:
            path = os.path.expanduser('~') + '/ipscanner/'
            os.makedirs(path, exist_ok=True)
            with open(path + 'results_' + self.mode, 'w') as file:
                file.writelines(','.join(self.inv_title) + '\n')
                for key, val in self.inventory.items():
                    file.writelines(f'{key},{val["type"]},{val["ip"]},{val["ping"]}\n')
            print(f"\nInventory report has exported -> {path + 'results_' + self.mode}\n")

    # Helpers

    @staticmethod
    def ip_validate(ip):
        regex = r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
        return True if (re.search(regex, ip)) else False

    @staticmethod
    def ping(ip, fast, process):
        if fast == '3':
            res = subprocess.run(['timeout', '0.2', 'ping', '-c', '1', ip], capture_output=process)
        elif fast == '2':
            res = subprocess.run(['ping', '-c', '1', '-w', '1', ip], capture_output=process)
        else:
            res = subprocess.run(['ping', '-c', '1', ip], capture_output=process)
        return 'Success!' if res.returncode == 0 else 'No response.'

    def options(self):
        fast_mode = self.entry('Select scan mode. (1) for normal mode | (2) for fast mode | (3) for ultra mode: ', True)
        process = self.entry('Print the scan process(y/n?): ') == 'y'
        output = self.entry('Create a scan report at the end(y/n?): ') == 'y'
        return fast_mode, process, output

    @staticmethod
    def entry(message, num=False):
        while True:
            inp = input(message).lower()
            if num and inp not in ('1', '2', '3') or not num and inp not in ('y', 'n'):
                print('Invalid entry.')
            else:
                return inp

    # Print methods

    def print_range(self, out):
        if self.mode.startswith('i'):
            interface = list(self.interfaces.keys())[list(self.interfaces.values()).index(self.mode.split()[1])]
            info = f'Interface: {interface} | {self.mode.split()[1]}'
        else:
            info = f'{self.mode.split()[1]} - {self.mode.split()[1]}'
        summary = f'\n{len(self.ip_list)} IP scanned in {(self.end_time - self.start_time).total_seconds()} seconds.'
        output = '*' * len(summary) + '\n' + info.center(len(summary)) + '\n' + '*' * len(summary)
        for key, val in self.ip_list.items():
            output += f'\n{key}: {val}'
        output += '\n' + '*' * len(summary) + summary + '\n' + '*' * len(summary) + '\n'
        print(output)
        if out:
            path = os.path.expanduser('~') + '/ipscanner/'
            os.makedirs(path, exist_ok=True)
            filename = 'report_' + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + '.txt'
            with open(path + filename, 'w') as file:
                file.write(output)
            print(f'Scan report has exported -> {path + filename}\n')

    def print_report(self):
        space = self.lengths()
        print((sum(space) + len(space) - 1) * '*')
        print(self.line_create(space, self.inv_title))
        print(self.line_create(space))
        for key, val in self.inventory.items():
            print(self.line_create(space, [key, val['type'], val['ip'], val['ping']]))
        print((sum(space) + len(space) - 1) * '*')
        print(f'{len(self.inventory)} host scanned in {(self.end_time - self.start_time).total_seconds()} seconds.')
        print((sum(space) + len(space) - 1) * '*')

    @staticmethod
    def line_create(values, items=None):
        string = []
        if items is not None:
            for i in range(len(items)):
                string.append(items[i].center(values[i]))
            return '|'.join(string)
        else:
            for num in values:
                string.append('*' * num)
            return '*'.join(string)

    def lengths(self):
        spaces = [len(title) for title in self.inv_title]
        for key, val in self.inventory.items():
            spaces[0] = len(key) if len(key) > spaces[0] else spaces[0]
            for i in range(len(val)):
                if len(list(val.values())[i]) > spaces[i + 1]:
                    spaces[i + 1] = len(list(val.values())[i])
        return [num + 2 for num in spaces]

    # Information

    @staticmethod
    def usage():
        print('',
              'Usage:',
              '',
              '\tpython ipscanner.py [option] [argument]',
              '',
              'Options:',
              '',
              '\t-i | Interface scan. Without argument, select from interface list.',
              '',
              '\t\tpython ipscanner.py -i',
              '\t\tpython ipscanner.py -i eth0',
              '\t\tpython ipscanner.py -i bond2',
              '',
              '\t-r | IP range scan.',
              '',
              '\t\tpython ipscanner.py -r startIP-endIP',
              '\t\tpython ipscanner.py -r 192.168.1.192-192.168.1.255',
              '',
              '\t-n | Scan from selected inventory report. Only accepts .csv files.',
              '',
              '\t\tpython ipscanner.py -n report.csv',
              '',
              'Features:',
              '',
              '\tScan mode     : Determines how long to wait the ping response. Normal mode waits a',
              '\t                single response fast mode waits 1s and ultra mode waits 200ms. On',
              '\t                stable and fast networks average ping response is less then 50ms.',
              '',
              '\tPrint process : Prints the ping processes during the scan.',
              '',
              '\tExport result : Exports the scan result under home directory.',
              '\t                Full path -> ~/ipscanner/',
              '',
              sep='\n')
        exit()


scanner = IPScanner()
scanner.main(sys.argv)

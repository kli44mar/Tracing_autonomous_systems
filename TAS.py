import argparse
import re
import subprocess
import sys
from urllib.request import urlopen
from prettytable import PrettyTable

reIP = re.compile(r'\[([\d\.]+?)\]')
reAS = re.compile(r'origin: *AS([\w]+?)\n')
reCountry = re.compile(r'country: *([A-Za-z]+?)\n')


def parse(site, reg):
    a = reg.findall(site)
    if a:
        return a[0]
    return 'Нет данных'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Трассировка автономных систем')
    parser.add_argument('-ip', '--ip', help='Ip адрес', required=False)
    parser.add_argument('-d', '--domain', help='Домен сайта', required=False)
    args = parser.parse_args()
    ip_m = []
    arg = ''
    if args.ip:
        arg = args.ip
    elif args.domain:
        arg = args.domain
    else:
        print("Неправильно введены данные")
        sys.exit()
    with subprocess.Popen(['tracert', arg], stdout=subprocess.PIPE) as proc:
        while True:
            line = proc.stdout.readline()
            if line:
                if len(re.findall(r'\*', str(line))) > 2:
                    break
                res = re.findall(reIP, str(line))
                if res:
                    ip_m.append(res[0])
            else:
                print("Проверьте подключение")
                sys.exit()
    ip_m.pop(0)
    td_data = []
    th = ['№', 'IP', 'AS', 'Country']
    table = PrettyTable(th)
    i = 1
    for ip in ip_m:
        url = f"https://www.nic.ru/whois/?searchWord={ip}"
        with urlopen(url) as f:
            site = f.read().decode('utf-8')
            td_data.append(i)
            td_data.append(ip)
            td_data.append(parse(site, reAS))
            td_data.append(parse(site, reCountry))
        i += 1
    while td_data:
        table.add_row(td_data[:4])
        td_data = td_data[4:]
    print(table)


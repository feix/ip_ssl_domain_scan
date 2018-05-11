#!/usr/bin/env python3

import re
import os
import sys
import json
import socket
import sqlite3
import asyncio

ROOT = os.path.dirname(os.path.abspath(__file__))


def prepare_db(db_name="./results.db"):
    conn = sqlite3.connect(db_name)
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS ip_domain(ip text, domains text)')
    conn.commit()
    return conn


# prepare masscan, return masscan_bin path
def prepare_masscan():
    masscan_path = '../masscan'
    masscan_bin = os.path.join(masscan_path, 'bin', 'masscan')
    if not os.path.exists(masscan_bin):
        # Download and Build masscan from https://github.com/robertdavidgraham/masscan.git
        os.system('git clone https://github.com/robertdavidgraham/masscan.git {masscan_path} && cd {masscan_path} && make -j'.format(masscan_path=masscan_path))
    return masscan_bin


# scan target network, write result to output file
def execute_masscan(masscan_bin, output, target='127.0.0.1/32', paused=False):
    if paused:
        command = [masscan_bin, '-c', target]
    else:
        command = [masscan_bin, '-p443', target, '--banners', '--exclude 255.255.255.255', '-oJ {output}'.format(output=output)]
    print(' '.join(command))
    os.system(' '.join(command))


def remove_last_comma(output):
    if os.stat(output).st_size > 0:
        os.system('sed -i "$(( $(wc -l < {output}) - 1 )),\$s/,$//g" {output}'.format(output=output))
        return True


async def resolve_unmatched_domain(ip, domains):
    try:
        # network io
        (resolve_domain, _, _) = await socket.gethostbyaddr(ip)
    except:
        return domains
    if not resolve_domain:
        return domains
    unmatched_domains = []
    for domain in domains:
        domain_regex = '^{}$'.format(domain.replace('*', '.*'))
        if re.match(domain_regex, resolve_domain):
            continue
        else:
            unmatched_domains.append(domain)
    return unmatched_domains


async def handle_result(conn, result):
    ip = result['ip']
    service = result['ports'][0].get('service')
    if not service or service['name'] != 'ssl':
        return ip, []
    domains = service['banner'].split(', ')[1:]
    unmatched_domains = await resolve_unmatched_domain(ip, domains)
    if len(unmatched_domains):
        print(ip, unmatched_domains, flush=True)
        cur = conn.cursor()
        cur.execute('INSERT INTO ip_domain VALUES (?, ?)', (ip, ','.join(domains)))
        conn.commit()


def handle_results(conn, output):
    if not remove_last_comma(output):
        print("fail to remove last comma.")
        return
    # file io
    with open(output) as f:
        results = json.load(f)
        tasks = []
        for result in results:
            tasks.append(asyncio.ensure_future(handle_result(conn, result)))
        loop = asyncio.get_event_loop()
        print('test asyncio', flush=True)
        loop.run_until_complete(asyncio.wait(tasks))


def usage():
    pass


def main():
    if len(sys.argv) > 1:
        paused = False
        target = ' '.join(sys.argv[1:])
    else:
        paused = True
        target = 'paused.conf'
    if paused and not os.path.exists(os.path.join(ROOT, target)):
        usage()
        return
    if len(target) < 40:
        target_name = target
    else:
        target_name = '{}_etc'.format(sys.argv[1])
    if paused:
        output = os.system("awk '$1 ~ /output-filename/ {print $3}' {}".format(target))
    else:
        output = './results/masscan_{}.json'.format(target_name.replace('/', '_').replace(' ', '_'))
    conn = prepare_db()
    masscan_bin = prepare_masscan()
    execute_masscan(masscan_bin, output, target, paused)
    handle_results(conn, output)
    conn.close()


if __name__ == '__main__':
    main()

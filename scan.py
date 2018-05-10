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
def execute_masscan(masscan_bin, output, target='127.0.0.1/32'):
    command = [masscan_bin, '-p443', target, '--banners', '--exclude 255.255.255.255', '-oJ {output}'.format(output=output)]
    os.system(' '.join(command))


def remove_last_comma(output):
    os.system('test -s {output} && sed -i "$(( $(wc -l < {output}) - 1 )),\$s/,$//g" {output}'.format(output=output))


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
    remove_last_comma(output)
    # file io
    with open(output) as f:
        results = json.load(f)
        tasks = []
        for result in results:
            tasks.append(asyncio.ensure_future(handle_result(conn, result)))
        loop = asyncio.get_event_loop()
        print('test asyncio', flush=True)
        loop.run_until_complete(asyncio.wait(tasks))


def main():
    target = '111.161.64.48/24'
    if len(sys.argv) > 1:
        target = sys.argv[1]
    conn = prepare_db()
    masscan_bin = prepare_masscan()
    output = './results/masscan_{}.json'.format(target.replace('/', '_'))
    execute_masscan(masscan_bin, output, target)
    handle_results(conn, output)
    conn.close()


if __name__ == '__main__':
    main()

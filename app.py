#!/usr/bin/env python3

import os
import json
import falcon
import sqlite3

ROOT = os.path.dirname(os.path.abspath(__file__))


def get_conn():
    conn = sqlite3.connect(os.path.join(ROOT, "./results.db"))
    return conn


class Domains(object):

    def on_get(self, req, resp):
        domain = req.get_param('domain') or 'qq.com'
        conn = get_conn()
        cur = conn.cursor()
        columns = ['ip', 'domains']
        results = cur.execute("SELECT * FROM ip_domain WHERE domains LIKE ?", ('%{0}%'.format(domain), )).fetchall()
        conn.commit()
        items = [dict(zip(columns, result)) for result in results]
        resp.body = json.dumps(items)


class Total(object):

    def on_get(self, req, resp):
        conn = get_conn()
        cur = conn.cursor()
        results = cur.execute("SELECT COUNT(1) FROM ip_domain").fetchall()
        conn.commit()
        resp.body = json.dumps(results[0][0])


api = falcon.API()
api.add_route('/domains', Domains())
api.add_route('/total', Total())
api.add_static_route('/', os.path.join(ROOT, './static'))

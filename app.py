#!/usr/bin/env python3

import os
import json
import falcon
import sqlite3

ROOT = os.path.dirname(os.path.abspath(__file__))


class Domains(object):

    def on_get(self, req, resp):
        domain = req.get_param('domain') or 'qq.com'
        conn = sqlite3.connect(os.path.join(ROOT, "./results.db"))
        cur = conn.cursor()
        columns = ['ip', 'domains']
        results = cur.execute("SELECT * FROM ip_domain WHERE domains LIKE ?", ('%{0}%'.format(domain), )).fetchall()
        conn.commit()
        resp.body = json.dumps([dict(zip(columns, result)) for result in results])


api = falcon.API()
api.add_route('/domains', Domains())
api.add_static_route('/', os.path.join(ROOT, './static'))
import os
import json
import xmltodict
import re
import mariadb
from flask import Flask
app = Flask(__name__)

sec_headers = dict()
sec_headers_id = 0


@app.route("/cmdb/relation/eitsbot/http_sec_headers")
def cmdb():
    cur = db().cur
    conn = db().conn
    cur.execute("SELECT * FROM archi_import WHERE url IS NOT NULL")
    rows = cur.fetchall()
    json_data = []

    for row in rows:
        ext_ipv4 = get_ext_ipv4(row)
        global sec_headers
        sec_headers = dict()
        global sec_headers_id
        sec_headers_id = 0
        os.system(
            "nmap -oX nmap_output.xml --script http-security-headers -p 443 " + ext_ipv4)
        f = open("nmap_output.xml")
        xml_content = f.read()
        f.close()
        matching_objects = []
        answer = []
        answer = process_json(xmltodict.parse(xml_content))
        result = ''

        for key, value in answer.items():
            i = 0
            for item, val in value.items():
                if re.search(r'Header:', val, re.IGNORECASE):
                    tempval = val.split('Header:')
                    val = tempval[1]
                    val = val.lstrip(' ')
#                if item == 'key' and not re.search(r'Strict_Transport_Security', val, re.IGNORECASE) and not re.search(r'X_XSS_Protection', val, re.IGNORECASE) and not re.search(r'Cookie', val, re.IGNORECASE):
#                    break
                if i == 0:
                    result += val + ': '
                    i = 1
                elif i == 1:
                    result += val + '; '
                    i = 0
        json_data.append(
            {
                "archi_id": row[0],
                "url": row[6],
                "ext_ipv4": ext_ipv4,
                "sec_headers": result

            }

        )
    return json.dumps(json_data)


def process_json(json_obj):

    global sec_headers_id
    # Iterate over the key-value pairs in the dictionary
    for key, value in json_obj.items():
        # If the value is a dictionary, recursively process it
        if isinstance(value, dict):
            process_json(value)
        # If the value is a list, iterate over the elements and process them
        elif isinstance(value, list):
            for element in value:
                if isinstance(element, dict):
                    process_json(element)
                else:
                    if key == "@key":
                        sec_headers_id += 1
                        sec_headers[str(sec_headers_id)] = {
                            'key': None, 'value': None}
                        sec_headers[str(sec_headers_id)]['key'] = element
                    if key == "elem" and sec_headers[str(sec_headers_id)]['value'] == None:
                        sec_headers[str(sec_headers_id)]['value'] = element

        # Otherwise, do something with the key and value
        else:
            if key == "@key":
                sec_headers_id += 1
                sec_headers[str(sec_headers_id)] = {'key': None, 'value': None}
                sec_headers[str(sec_headers_id)]['key'] = value
            if key == "elem" and sec_headers[str(sec_headers_id)]['value'] == None:
                sec_headers[str(sec_headers_id)]['value'] = value
    return sec_headers


def get_ext_ipv4(row):
    cur = db().cur
    conn = db().conn
    name = "CMS (" + row[2] + ")"
    ext_ipv4 = ""
    cur.execute("SELECT * FROM archi_import WHERE name = ?", (name,))
    rows2 = cur.fetchall()
    for row2 in rows2:
        cur.execute(
            "SELECT * FROM archi_graph WHERE source = ? OR target = ?", (row2[0], row2[0]))
        rows3 = cur.fetchall()
        for row3 in rows3:
            cur.execute(
                "SELECT * FROM archi_import WHERE (sid = ? OR sid = ?) AND ext_ipv4 IS NOT NULL", (row3[1], row3[2]))
            rows4 = cur.fetchall()
            if rows4[0][8] != None:
                ext_ipv4 = rows4[0][8]
                break
    return ext_ipv4


class database:
    def __init__(self):
        try:
            self.conn = mariadb.connect(
                user="root",
                password="root",
                host="localhost",
                port=3306,
                database="eits"

            )
        except mariadb.Error as e:
            print(f"Error connecting to MariaDB Platform: {e}")
            sys.exit(1)
        self.cur = self.conn.cursor()


def db():
    return database()

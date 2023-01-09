import os
import json
import xmltodict
import re
import mariadb
from flask import Flask
app = Flask(__name__)
http_robots = []


@app.route("/cmdb/relation/eitsbot/robots_check")
def cmdb():
    cur = db().cur
    conn = db().conn
    cur.execute("SELECT * FROM archi_import WHERE url IS NOT NULL")
    rows = cur.fetchall()
    json_data = []

    for row in rows:
        ext_ipv4 = get_ext_ipv4(row)
        os.system(
            "nmap -oX nmap_output.xml --script http-robots.txt.nse -p 443 " + ext_ipv4)
        f = open("nmap_output.xml")
        xml_content = f.read()
        f.close()
        matching_objects = []
        global http_robots
        http_robots = []
        tempanswer = process_json(xmltodict.parse(xml_content))
        answer = []

        for item in tempanswer:
            tempitem = item.split('\n', 1)
            item = tempitem[1]
            item = item.replace('\n', '')
            itemlist = re.split(' ', item)
            answer.extend(itemlist)
        result = ''

        for item in answer:
            result += item + '; '
        result = result.rstrip('; ')
        json_data.append(
            {
                "archi_id": row[0],
                "url": row[6],
                "ext_ipv4": ext_ipv4,
                "disallowed": result

            }
        )
    return json.dumps(json_data, indent=4, sort_keys=True)


def process_json(json_obj):

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
                    if key == "@output":
                        http_robots.append(element)

        # Otherwise, do something with the key and value
        else:
            if key == "@output":
                http_robots.append(value)

    return http_robots


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

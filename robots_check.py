import os
import json
import xmltodict
import re
import mariadb
from flask import Flask
app = Flask(__name__)
http_robots = []
http_robots_id = 0
@app.route("/cmdb/relation/eitsbot/http_robots")
def cmdb():
    cur = db().cur
    conn = db().conn
    cur.execute("SELECT * FROM archi_import WHERE ext_ipv4 IS NOT NULL")
    rows = cur.fetchall()
    json_data = []
    for row in rows:
        os.system("nmap -oX nmap_output.xml --script http-robots.txt.nse -p 443 " + row[8])
        f = open("nmap_output.xml")
        xml_content = f.read()
        f.close()
        matching_objects = []
        global http_robots
        http_robots = []
        data1 = json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)
        data = json.loads(data1)
        print(data1)
        tempanswer = process_json(data)
        print(tempanswer)
        answer = []
        for item in tempanswer:
            tempitem = item.split('\n', 1)
            item = tempitem[1]
            item = item.replace('\n', '')
            itemlist = re.split(' ', item)
            answer.extend(itemlist)
            print(item)
        print(answer)
        result = ''
        for item in answer:
            result += item + '; '
        result = result.rstrip('; ')
        json_data.append(
            {
                "archi_id": row[0],
                "url": row[6],
                "ip": row[8],
                "disallowed": result

            }
        )
    return json.dumps(json_data, indent=4, sort_keys=True)

def process_json(json_obj):

    global http_robots_id
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
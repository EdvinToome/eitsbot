import os
import json
import xmltodict
import re
import mariadb
from flask import Flask
app = Flask(__name__)
http_check = dict()
@app.route("/cmdb/relation/eitsbot/http_check")
def cmdb():
    cur = db().cur
    conn = db().conn
    cur.execute("SELECT * FROM archi_import WHERE ext_ipv4 IS NOT NULL")
    rows = cur.fetchall()
    json_data = []
    for row in rows:
        os.system("nmap -oX nmap_output.xml --script http-server-header -p 443 " + row[8])
        f = open("nmap_output.xml")
        xml_content = f.read()
        f.close()
        data1 = json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)
        data = json.loads(data1)
        print(data1)
        answer = process_json(data)
        print(answer)
        json_data.append(
            {
                "archi_id": row[0],
                "url": row[6],
                "ip": row[8],
                answer['key']: answer['value']

            }
        )
        os.system("nmap -oX nmap_output.xml --script http-waf-detect -p 443 " + row[8])
        f = open("nmap_output.xml")
        xml_content = f.read()
        f.close()
        data1 = json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)
        data = json.loads(data1)
        print(data1)
        answer = process_json(data)
        print(answer)
        waf = False
        if re.search("DS/IPS/WAF detected:", answer['value']):
            waf = True
        json_data[-1].update(
            {
                "waf": waf
            }
        )
    return json.dumps(json_data, indent=4, sort_keys=True)








def process_json(json_obj):
    global http_check
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
                        http_check['value'] = element
                    if key == "@id":
                        http_check['key'] = element


        # Otherwise, do something with the key and value
        else:
            if key == "@output":
                http_check["value"] = value
            if key == "@id":
                http_check["key"] = value
 
    return http_check

if __name__ == "__main__":
    main()

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
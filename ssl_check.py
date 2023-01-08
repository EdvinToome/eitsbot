import os
import json
import xmltodict
import re
import mariadb
from flask import Flask
app = Flask(__name__)
ssl_check = dict()
@app.route("/cmdb/relation/eitsbot/ssl_check")
def cmdb():
    cur = db().cur
    conn = db().conn
    cur.execute("SELECT * FROM archi_import WHERE ext_ipv4 IS NOT NULL")
    rows = cur.fetchall()
    json_data = []
    for row in rows:
        os.system("nmap -oX nmap_output.xml --script ssl-enum-ciphers -p 443 " + row[8])
        f = open("nmap_output.xml")
        xml_content = f.read()
        f.close()
        data1 = json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)
        data = json.loads(data1)
        answer = process_json(data)
        answer = answer["value"].split("\n")
        result = ''
        for item in answer:
            item = item.lstrip(' ')
            item = item.rstrip(' ')
            if re.search("TLSv", item):
                result = result + item + ' '
            if re.search("TLS_", item):
                item = item.split(" ")
                result = result + item[0]+ ' ' + item[-1] + "; "
        result = result.rstrip('; ')
        print(result)
        json_data.append(
            {
                "archi_id": row[0],
                "url": row[6],
                "ip": row[8],
                "ciphers": result

            }
        )
    return json.dumps(json_data, indent=4, sort_keys=True)








def process_json(json_obj):
    global ssl_check
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
                        ssl_check['value'] = element
                    if key == "@id":
                        ssl_check['key'] = element


        # Otherwise, do something with the key and value
        else:
            if key == "@output":
                ssl_check["value"] = value
            if key == "@id":
                ssl_check["key"] = value
 
    return ssl_check



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

if __name__ == "__main__":
    main()
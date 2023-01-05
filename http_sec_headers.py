import os
import json
import xmltodict
import re
os.system("nmap -oX nmap_output.xml --script http-security-headers -p 443 195.80.116.171")
f = open("nmap_output.xml")

xml_content = f.read()

f.close()
matching_objects = []
data1 = json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)
data = json.loads(data1)


sec_headers = dict()
sec_headers_id = 0
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
                        sec_headers[str(sec_headers_id)] = {'key': None, 'value': None}
                        sec_headers[str(sec_headers_id)]['key'] = element
                    if key == "elem" and sec_headers[str(sec_headers_id)]['value'] == None:
                        sec_headers[str(sec_headers_id)]['value'] = element

        # Otherwise, do something with the key and value
        else:
            if key == "@key":
                sec_headers_id += 1
                sec_headers[str(sec_headers_id)] = {'key': None, 'value': None}
                sec_headers[str(sec_headers_id)]['key'] = value
            if key == "elem" and  sec_headers[str(sec_headers_id)]['value'] == None:
                sec_headers[str(sec_headers_id)]['value'] = value
    return sec_headers

answer = process_json(data)
result = ''
for key, value in answer.items():
    i = 0
    for item, val in value.items():
        if re.search(r'Header:', val, re.IGNORECASE):
            tempval = val.split('Header:')
            val = tempval[1]
            val = val.lstrip(' ')
        if item == 'key' and not re.search(r'Strict_Transport_Security', val, re.IGNORECASE) and not re.search(r'X_XSS_Protection', val, re.IGNORECASE) and not re.search(r'Cookie', val, re.IGNORECASE):
            break
        if i == 0:
            result += val + ': '
            i = 1
        elif i == 1:
            result += val + '; '
            i = 0
print(result)

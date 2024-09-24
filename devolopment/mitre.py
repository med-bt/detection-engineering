import requests
import json
import sys,toml,os
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
headers = {
    'accept':'application/json'
}

data = requests.get(url,headers=headers).json()
mitre_mapped = {}

# with open("mitre.json",'r') as f:
#     data = json.load(f)

print("file loaded")

for object in data["objects"]:
    tactics = []
    if object['type'] == 'attack-pattern':
        if "external_references" in object:
            for reference in object['external_references']:
                if 'external_id' in reference:
                    if reference['external_id'].startswith('T'):
                        for tactic in object['kill_chain_phases']:
                            tactics.append(tactic)
                        url = reference['url'] 
                        technique = reference['external_id']
                        name = object['name']
                        
                        if 'x_mitre_deprecated' in object:
                            deprecated = object['x_mitre_deprecated']
                            filtered_object = {"tactics" : str(tactics), "technique" : technique,'name':name,'url' : url,'deprecated':deprecated}
                            mitre_mapped[technique] = filtered_object

                        else :
                            filtered_object = {"tactics" : str(tactics), "technique" : technique,'name':name,'url' : url,'deprecated':"false"}
                            mitre_mapped[technique] = filtered_object


directory = "C:\\Users\\Think\\Desktop\\detection\\custom_alerts"
alert_data = {}
for root, dirs, files in os.walk(directory):
    for file in files:
        if file.endswith(".toml"):
            file_path = os.path.join(root, file)
            with open (file_path,'r') as alert:
                alert = toml.load(alert)
                filtered_object_array = []
                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK":
                    for threat in alert['rule']['threat']:
                        technique_id = threat['technique'][0]['id']
                        technique_name = threat['technique'][0]['name']
                        if "tactic" in threat:
                            tactic = threat['tactic']['name']
                        else:
                            tactic = 'none'
                        if 'subtechnique' in threat['technique'][0]:
                            subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                        else:
                            subtechnique_id = 'none'
                            subtechnique_name = 'none'
                        filtered_object = {'tactic':tactic,'technique_id':technique_id,'technique_name':technique_name,"subtechnique_id":subtechnique_id,'subtechnique_name':subtechnique_name}
                        filtered_object_array.append(filtered_object)
                        alert_data[file] = filtered_object_array
                        # print (file + " : "+technique_id+" : "+technique_name +" : " + tactic)
mitre_tactic_list = ['none','reconnaissance','resource development','initial access','execution','persistence','privilege escalation','defense evasion','credential access','discovery','lateral movement','collection','command and control','exfiltration','impact']

for file in alert_data:
    for line in alert_data[file]:
        tactic=line['tactic'].lower()
        technique_id=line['technique_id']
        subtechnique_id = line['subtechnique_id']

        # Check to ensure MITRE Tactic exists
        if tactic not in mitre_tactic_list:
            print("The MITRE Tactic supplied does not exist: " + "\"" + tactic + "\"" + " in " + file)
            failure = 1
       # Check to make sure the MITRE Technique ID is valid
        try:
            if mitre_mapped[technique_id]:
                pass
        except KeyError:
            print("Invalid MITRE Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
            failure = 1
       # Check to see if the MITRE TID + Name combination is Valid
        try:
            mitre_name = mitre_mapped[technique_id]['name']
            alert_name = line['technique_name']
            if alert_name != mitre_name:
                print("MITRE Technique ID and Name Mismatch in " + file + " EXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                failure = 1
        except KeyError:
            pass

       # Check to see if the subTID + Name Entry is Valid
        try:
            if subtechnique_id != "none":
                mitre_name = mitre_mapped[subtechnique_id]['name']
                alert_name = line['subtechnique_name']
                if alert_name != mitre_name:
                    print("MITRE Sub-Technique ID and Name Mismatch in " + file + " EXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                    failure = 1
        except KeyError:
            pass

       # Check to see if the technique is deprecated
        try:
            if mitre_mapped[technique_id]['deprecated'] == True:
                 print("Deprecated MITRE Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
                 failure = 1
        except KeyError:
            pass
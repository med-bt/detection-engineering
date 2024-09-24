import requests
import os
import toml
api_key = os.environ("ELASTIC_KEY")
url = "https://f668bc46801544f3a1ad2cc190fc0de8.eastus2.azure.elastic-cloud.com:9243/api/detection_engine/rules?rule_id="
headers = {
    'Content-Type': 'application/json',
    'Authorization': 'ApiKey '+api_key,
    'kbn-xsrf': 'true' 
    }
directory = "C:\\Users\\Think\\Desktop\\detection\\custom_alerts"

for root, dirs, files in os.walk(directory):
    for file in files:
        data = "{\n"
        if file.endswith(".toml"):
            file_path = os.path.join(root, file)
            with open(file_path,'r') as t:
                alert = toml.load(t)
                
                if alert['rule']['type'] == "query": # query based alert
                    required_fields = ['author','description', 'name','rule_id','risk_score','severity','type','query',"threat"]
                elif alert['rule']['type'] == "eql": # event correlation alert
                    required_fields = ['author','description', 'name','rule_id','risk_score','severity','type','query','language',"threat"]
                elif alert['rule']['type'] == "threshold": # threshold based alert
                    required_fields = ['author','description', 'name','rule_id','risk_score','severity','type','query','threshold',"threat"]
                else:
                    print("Unsupported rule type found in: " + file_path)
                    break
            
            for field in alert['rule']:
                if field in required_fields:
                    if type(alert['rule'][field]) == list:
                        data += " \""+field+"\" : "+str(alert['rule'][field]).replace("'","\"")+", \n"
                    elif type(alert['rule'][field]) == str:
                        data += " \""+field+"\" : \""+str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"")+"\" , \n"
                    elif type(alert['rule'][field]) == int:
                        data += " \""+field+"\" : "+str(alert['rule'][field])+", \n"
            data+= " \"enabled\": true\n}"
        rule_id = alert['rule']['rule_id']
        full_path = url+rule_id
        elastic_data = requests.put(full_path,headers=headers,data=data).json()
        print(elastic_data)
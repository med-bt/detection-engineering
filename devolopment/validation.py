import toml
import os

def validate(file_path):
    try:
        with open(file_path, 'r') as f:
            alert = toml.load(f)
            required_fields = ['name', 'description', 'risk_score', 'severity', 'type', 'query']
            present_fields = []
            missing_fields = []

            rule = alert.get("rule", {})
            rule_type = rule.get("type")

            if rule_type is not None:
                if rule_type == "threshold":
                    required_fields.append("threshold")
                elif rule_type == "eql":
                    required_fields.append("language")
                elif rule_type == "query":
                    pass  # No additional fields needed
                else:
                    print(f"Unsupported type value: {rule_type} in {file_path}")
                    return
            else:
                print(f"'type' field does not exist in {file_path}")
                return

            # Collect present fields
            for field in rule:
                present_fields.append(field)

            # Identify missing fields
            for r in required_fields:
                if r not in present_fields:
                    missing_fields.append(r)

            if missing_fields:
                print(f"The following fields do not exist in {file_path}: {missing_fields}")
            else:
                print(f"All required fields are present in {file_path}")

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except toml.TomlDecodeError:
        print(f"Error decoding TOML file: {file_path}")

# Path to the directory containing TOML files
directory = "C:\\Users\\Think\\Desktop\\detection\\custom_alerts"

for root, dirs, files in os.walk(directory):
    for file in files:
        if file.endswith(".toml"):
            file_path = os.path.join(root, file)
            validate(file_path)

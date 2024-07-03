import json
import os
import boto3
import sys
from datetime import datetime

# Function to upload data to DynamoDB
def upload_to_dynamodb(current_report, table_name, region_name):
    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb', region_name=region_name)
    table = dynamodb.Table(table_name)

    # Upload the vulnerabilities
    response = table.put_item(
        Item={
            'id': str(uuid.uuid4()),
            'timestamp': current_report['timestamp'],
            'high': current_report['high'],
            'medium': current_report['medium'],
            'low': current_report['low']
        }
    )
    return response

# Load the SARIF file
def load_sarif(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Extract runs, results, and rules
def parse_sarif(sarif_data):
    runs_data = sarif_data['runs']
    rules = runs_data[0]['tool']['driver']['rules']
    results = runs_data[0]['results']

    # Initialize counters and storage for vulnerabilities
    total_vulnerabilities = 0
    high_vulnerabilities = []
    medium_vulnerabilities = []
    low_vulnerabilities = []

    # Severity mapping
    severity_mapping = {
        "error": "High",
        "warning": "Medium",
        "note": "Low"
    }

    # Current timestamp
    current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Find matches between rule ids and result rule ids
    for rule in rules:
        rule_id = rule['id']
        rule_severity = severity_mapping.get(rule.get('defaultConfiguration', {}).get('level'), "Unknown")
        rule_description = rule['shortDescription']['text']
        
        for result in results:
            if result['ruleId'] == rule_id:
                result_severity = severity_mapping.get(result['level'], "Unknown")
                for location in result['locations']:
                    vulnerability = {
                        'ruleName': rule_description,
                        'path': location['physicalLocation']['artifactLocation']['uri'],
                        'line': location['physicalLocation']['region']['startLine'],
                        'severity': result_severity,
                        'timestamp': current_timestamp
                    }
                    if result_severity == "High":
                        high_vulnerabilities.append(vulnerability)
                    elif result_severity == "Medium":
                        medium_vulnerabilities.append(vulnerability)
                    elif result_severity == "Low":
                        low_vulnerabilities.append(vulnerability)
                    total_vulnerabilities += 1

    current_report = {
        'timestamp': current_timestamp,
        'high': high_vulnerabilities,
        'medium': medium_vulnerabilities,
        'low': low_vulnerabilities
    }

    return current_report

if __name__ == '__main__':
    file_path = 'snyk.sarif'
    region_name = os.getenv('AWS_REGION')
    table_name = os.getenv('DYNAMODB_TABLE_NAME')
    
    sarif_data = load_sarif(file_path)
    current_report = parse_sarif(sarif_data)
    
    upload_to_dynamodb(current_report, table_name, region_name)

    print(f"Report upload completed to DynamoDB table '{table_name}'.")

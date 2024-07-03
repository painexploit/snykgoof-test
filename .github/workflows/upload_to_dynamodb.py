import json
import boto3
import sys
import uuid
import os

def parse_sarif(file_path):
    with open(file_path, 'r') as f:
        sarif_data = json.load(f)
    
    vulnerabilities = {
        'Critical': [],
        'High': [],
        'Medium': [],
        'Low': []
    }

    # SARIF structure might vary, adjust the parsing as per the actual SARIF structure
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            severity = result.get('level')
            vulnerability_name = result.get('message', {}).get('text', 'Unknown vulnerability')
            if severity == 'error':
                vulnerabilities['Critical'].append(vulnerability_name)
            elif severity == 'warning':
                vulnerabilities['High'].append(vulnerability_name)
            elif severity == 'note':
                vulnerabilities['Medium'].append(vulnerability_name)
            else:
                vulnerabilities['Low'].append(vulnerability_name)
    
    return vulnerabilities

def upload_to_dynamodb(file_path, table_name):
    vulnerabilities = parse_sarif(file_path)

    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb', region_name=region_name)
    table = dynamodb.Table(table_name)

    # Upload the vulnerabilities
    response = table.put_item(
        Item={
            'id': str(uuid.uuid4()),
            'critical': vulnerabilities['Critical'],
            'high': vulnerabilities['High'],
            'medium': vulnerabilities['Medium'],
            'low': vulnerabilities['Low']
        }
    )
    return response

if __name__ == '__main__':
    file_path = sys.argv[1]
    table_name = os.getenv('DYNAMODB_TABLE_NAME')
    region_name = os.getenv('AWS_REGION')
    upload_to_dynamodb(file_path, table_name)

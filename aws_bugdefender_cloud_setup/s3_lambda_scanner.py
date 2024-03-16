import time
import json
import boto3
from datetime import datetime

ec2 = boto3.client('ec2')
ssm = boto3.client('ssm')
ssmwaiter = ssm.get_waiter('command_executed')
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

CLAMAV = 'clean'
DRWEB = 'clean'
SOPHOS = 'clean'

def save_result(uid, key):
    scanned_on = datetime.now().strftime("%y-%m-%d %H:%M:%S")
    table = dynamodb.Table('s3scanner')
    response = table.put_item(
       Item={
            'userid': uid,
            'objectkey': key,
            'scanned_on': scanned_on,
            'clamav': CLAMAV,
            'drweb': DRWEB,
            'sophos': SOPHOS
        }
    )
    return response


def process_response(instanceid, output):
    # SOPHOS ANTIVIRUS WORKER
    if instanceid == 'i-025364a0befeb1db0':
        global SOPHOS
        if ">>>" in output:
            SOPHOS = 'infected'
        elif output == 'error':
            SOPHOS = 'error'

    # DR.WEB ANTIVIRUS WORKER
    elif instanceid == 'i-0d8ff8c2a993056f4':
        global DRWEB
        if "virus" in output:
            DRWEB = 'infected'
        elif output == 'error':
            DRWEB = 'error'

    # CLAM ANTIVIRUS WORKER
    elif instanceid == 'i-0c57155132cc20788':
        global CLAMAV
        if 'FOUND' in output:
            CLAMAV = "infected"
        elif output == 'error' or 'Total errors:' in output:
            CLAMAV = 'error'


def execute_scanners(script):
    InstanceIds=['i-025364a0befeb1db0', 'i-0d8ff8c2a993056f4', 'i-0c57155132cc20788']

    # looping through instance ids
    #for instanceid in InstanceId:
    # command to be executed on instance
    response = ssm.send_command(
            InstanceIds=InstanceIds,
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [script]}
            )

    # fetching command id for the output
    command_id = response['Command']['CommandId']

    time.sleep(5)
    for instanceid in InstanceIds:
        try:
            ssmwaiter.wait(CommandId= command_id, InstanceId= instanceid, WaiterConfig={
                'Delay': 5,
                'MaxAttempts': 10
                }
            )
            # fetching command output
            output = ssm.get_command_invocation(CommandId=command_id, InstanceId=instanceid)
            #status = output['Status']
            print(output)
            stdout = output['StandardOutputContent']
            process_response(instanceid, stdout)
        except Exception as e:
            print(e)
            process_response(instanceid, 'error')


def lambda_handler(event, context):

    for record in event['Records']:
        body = json.loads(record["body"])
        if 'Records' in body:
            for data in body['Records']:
                key = data['s3']['object']['key']
                tempkey = key.split('/')
                key2 = tempkey[-1]
                uid = tempkey[0]
                bucket = data['s3']['bucket']['name']

                script = f"sudo PYTHONUSERBASE=/home/ubuntu/.local python3 /home/ubuntu/scanner.py {bucket} {key}"
                print(script)
                execute_scanners(script)

        response = {'CLAMAV': CLAMAV, 'DRWEB' : DRWEB, 'SOPHOS' : SOPHOS}
        print(response)

        res = save_result(uid, key2)
        print(res)

        resp = s3.delete_object(Bucket= bucket, Key= key)
        print(resp)
    return {
        'statusCode': 200,
        'body': json.dumps(response)
    }

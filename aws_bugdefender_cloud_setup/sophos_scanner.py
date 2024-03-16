#!/usr/bin/python3
import boto3
import uuid
import sys
import os

s3client = boto3.client('s3')
try:
    tempkey = '/tmp/' + str(uuid.uuid4())
    bucket = sys.argv[1]
    key = sys.argv[2]
    s3client.download_file(bucket, key, tempkey)
    os.system("savscan {}".format(tempkey))

except Exception as e:
    print(e)
finally:
    os.system("sudo rm {}".format(tempkey))

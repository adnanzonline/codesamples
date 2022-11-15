import json
import boto3
import base64
import datetime
import os
from datetime import date
from botocore.exceptions import ClientError
iam = boto3.client('iam')
secretmanager = boto3.client('secretsmanager')

def warning(uname):
    try:
	
		IAM_UserName=uname
		print (IAM_UserName)
		getpresecvalue=secretmanager.get_secret_value(SecretId=IAM_UserName,VersionStage='AWSPREVIOUS')
		preSecString = json.loads(getpresecvalue['SecretString'])
		preAccKey=preSecString['AccessKey']
		
		#GET CREATION DATE OF CURRENT VERSION OF ACCESS KEY
		curdate=getcursecvalue['CreatedDate']
		#GET TIMEZONE FROM CREATION DATE
		tz=curdate.tzinfo
		
		#CALCULATE TIME DIFFERENCE BETWEEN CREATION DATE AND TODAY
        diff=datetime.datetime.now(tz)-curdate
        diffdays=diff.days

	    #IF TIME DIFFERENCE IS MORE THAN x NUMBER OF DAYS THEN DEACTIVATE PREVIOUS KEY AND SEND A MESSAGE
		
        if diffdays >= 50:
	
        emailmsg="Your "+preAccKey+" is going to expire in next 10 days. Please recreate a new key. otherwise current key will be automated disabled and deleted"
        ops_sns_topic ='arn:aws:sns:eu-west-1:123456789012:Notification'
        sns_send_report = boto3.client('sns',region_name='eu-east-1')
        sns_send_report.publish(TopicArn=ops_sns_topic, Message=emailmsg, Subject="Warning for user"+ IAM_UserName)
    except ClientError as e:
        print (e)

def deactive_key(uname):
    try:
	    #GET PREVIOUS AND CURRENT VERSION OF KEY FROM SECRET MANAGER
        IAM_UserName=uname
        getpresecvalue=secretmanager.get_secret_value(SecretId=IAM_UserName,VersionStage='AWSPREVIOUS')
        preSecString = json.loads(getpresecvalue['SecretString'])
        preAccKey=preSecString['AccessKey']

        #CALCULATE TIME DIFFERENCE BETWEEN CREATION DATE AND TODAY
        iam.update_access_key(AccessKeyId=preAccKey,Status='Inactive',UserName=IAM_UserName)
        emailmsg="PreviousKey "+preAccKey+" has been disabled for IAM User"+IAM_UserName
        ops_sns_topic ='arn:aws:sns:eu-west-1:123456789012:Notification'
        sns_send_report = boto3.client('sns',region_name='us-east-1')
        sns_send_report.publish(TopicArn=ops_sns_topic, Message=emailmsg, Subject='Previous Key Deactivated')
        return
    except ClientError as e:
        print (e)

def delete_key(uname):
    try:
        IAM_UserName=uname
        print (IAM_UserName)
        getpresecvalue=secretmanager.get_secret_value(SecretId=IAM_UserName,VersionStage='AWSPREVIOUS')
        preSecString = json.loads(getpresecvalue['SecretString'])
        preAccKey=preSecString['AccessKey']

        keylist=iam.list_access_keys (UserName=IAM_UserName)
        for x in range(2):
            prevkeystatus=keylist['AccessKeyMetadata'][x]['Status']
            preacckeyvalue=keylist['AccessKeyMetadata'][x]['AccessKeyId']
            print (prevkeystatus)
            if prevkeystatus == "Inactive": 
                if preAccKey==preacckeyvalue:
                    print (preacckeyvalue)
                    iam.delete_access_key (UserName=IAM_UserName,AccessKeyId=preacckeyvalue)
                    emailmsg="PreviousKey "+preacckeyvalue+" has been deleted for user"+IAM_UserName
                    ops_sns_topic ='arn:aws:sns:eu-west-1:123456789012:Notification'
                    sns_send_report = boto3.client('sns',region_name='us-east-1')
                    sns_send_report.publish(TopicArn=ops_sns_topic, Message=emailmsg, Subject='Previous Key has been deleted')
                    return
                else:
                    print ("secret manager previous value doesn't match with inactive IAM key value")
            else:
                print ("previous key is still active")
        return
    except ClientError as e:
        print (e)
    
def lambda_handler(event, context):
    faction=event ["action"]
    fuser_name=event ["username"]
    if faction == "create":
        status = warning(fuser_name)
        print (status)
    elif faction == "deactivate":
        status = deactive_key(fuser_name)
        print (status)
    elif faction == "delete":
        status = delete_key(fuser_name)
        print (status)
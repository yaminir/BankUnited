#!/usr/bin/env python

"""
Copyright 2018 Amazon.com, Inc. or its affiliates.
All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
A copy of the License is located at
   http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file.
This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

This script is a custom python script which identifies the existing cloud watch log groups in an AWS account,
deletes the existing subscription filters and adds the central log destination as a subscription filter.

The script should be run on each application/ core account of BKU or Backbase.Log Destination will be created dynamically
following the naming convention.

Input Parameters:
1.Type of account which can be either BKU or Backbase.
2.Central Logging Account ID.
3.Log Destination Region

"""
###########
# Imports #
###########

from __future__ import print_function, absolute_import
from botocore.exceptions import ClientError
import boto3
import sys
import logging
import socket

###########
# Logging #
###########
logging.basicConfig()
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)

###########
# Globals #
###########
log_group_categories = ["Config","CT","VPC"]
count_log_groups = 0
log_group_prefix = []
log_subscription_client = boto3.client('logs')
log_group_client = boto3.client('logs')
ssm_client = boto3.client('ssm')

#############
# Functions #
#############
def getAccount():
    """
    Returns AWS accountID in which the custom python script is run.

    Parameters:
    None

    Returns:
    str: returns the AWS accountID in which the cloudwatch logs are generated.
    """
    try:
        sts_client = boto3.client('sts')
        aws_account_id = sts_client.get_caller_identity()['Account']
        return aws_account_id
    except Exception:
        logger.exception('An unexpected error occurred while trying to get AWS accoundID.')

def getAcctType():
    """
    Returns the input parameter to the custom python script and verifies if it is bku or backbase.

    Parameters:
    None

    Returns:
    str: returns the type of account passed as an input parameter to this custom python script.
    """
    try:
        type_of_acct = sys.argv[1]
        return type_of_acct
    except Exception:
        logger.exception('An unexpected error occurred while trying to get AWS Account type.')

def getLogGroupName(type_of_acct,aws_account_id,log_group_category):
    """
    Returns the log group name to search from the list of cloud watch log groups in app/ core AWS account.

    Parameters:
    type_of_acct : Account type passed an input to python script.
    aws_account_id : AWS Account ID fetched from account in which the python script is run.
    log_group_category: Log Group Category which is initialized as global.

    Returns:
    str: returns the log group search name.
    """
    try:
        log_group_search_name = type_of_acct+"-"+aws_account_id+"-"+log_group_category
        return log_group_search_name
    except Exception:
        logger.exception('An unexpected error occurred while trying to get Log Group prefix/Name to search.')

def getLogGroups(log_group_search_name):
    """
    Returns all the log groups for the log group category with the log group prefix.

    Parameters:
    log_group_search_name : Log group prefix for each log group category.

    Returns:
    str: returns all the log groups with the log group prefix
    """
    try:
        log_group_response = log_group_client.describe_log_groups(logGroupNamePrefix=log_group_search_name)
        return log_group_response
    except Exception:
        logger.exception('An unexpected error occurred while trying to fetch log groups with the log group prefix for each log group category.')

def listSubscriptionFilters(log_group_search_name):
    """
    Lists all the existing subscription filters for the log group fetched based on the log group prefix.

    Parameters:
    log_group_search_name : Log group prefix for each log group category.

    Returns:
    str: returns describe subscription filters API call response.
    """
    try:
        log_subscription_client = boto3.client('logs')
        subscription_filters_response = log_subscription_client.describe_subscription_filters(
                                logGroupName=log_group_search_name
                            )
        return subscription_filters_response
    except Exception:
        logger.exception('An unexpected error occurred while trying to list existing subscription filters of cloud watch log group with log group prefix.')

def putLogGroupprefix(log_group_search_name):
    """
    Appends all the log group prefixes for all the log group categories.

    Parameters:
    log_group_search_name : Log group prefix for each log group category.

    Returns:
    str: returns an appended array of log group prefixes for each iteration.
    """
    try:
        log_group_prefix.append(log_group_search_name)
        return log_group_prefix
    except Exception:
        logger.exception('An unexpected error occurred while trying to append log group prefix for each log group category.')

def deleteSubscriptionFilters(log_group_search_name,filter_name):
    """
    Lists all the existing subscription filters for the log group fetched based on the log group prefix.

    Parameters:
    log_group_search_name : Log group prefix for each log group category.
    filter_name : Subscription filter name fetched from describe subscription filters API call.

    Returns:
    str: returns deleted subscription filters API call response.
    """
    try:
        delete_subscription_response = log_subscription_client.delete_subscription_filter(
            logGroupName=log_group_search_name,
            filterName=filter_name
        )
        return delete_subscription_response
    except Exception:
        logger.exception('An unexpected error occurred while trying to delete existing subscription filters from cloud watch log groups with log group prefix.')

def createLogDestination(type_of_acct,log_group_category):
    """
    Returns the Log destination parameter name to search in SSM parameter store.

    Parameters:
    type_of_acct : Account type passed an input to python script.
    log_group_category: Log Group Category which is initialized as global.

    Returns:
    str: returns the log destination SSM parameter name.
    """
    try:
        log_destination_ssm_name = 'LogDestination'+type_of_acct+log_group_category
        return log_destination_ssm_name
    except Exception:
        logger.exception('An unexpected error occurred while trying to create log destination SSM parameter name.')

def getLogDestinationResponse(log_destination_ssm_name):
    """
    Returns the Log destination ARN from SSM parameter store.

    Parameters:
    log_destination_ssm_name : Log destination name from SSM parameter store.

    Returns:
    str: returns the log destination response from SSM API call using the log destination name.
    """
    try:
        log_destination_response = ssm_client.get_parameter(Name=log_destination_ssm_name)
        return log_destination_response
    except Exception:
        logger.exception('An unexpected error occurred while trying to create log destination response from SSM get parameter API call.')


def getLogDestinationArn(log_destination_response):
    """
    Returns the Log destination ARN from SSM parameter store.

    Parameters:
    log_destination_response : Log destination response from get paramter SSM API call.

    Returns:
    str: returns the log destination ARN paramter value using the log destination name.
    """
    try:
        destination = log_destination_response['Parameter']['Value']
        return destination
    except Exception:
        logger.exception('An unexpected error occurred while trying to fetch Log destination ARN value.')

def createSubscriptionFilterName(type_of_acct,log_group_category):
    """
    Returns the Subscription filter name.

    Parameters:
    type_of_acct : Account type passed an input to python script.
    log_group_category: Log Group Category which is initialized as global.

    Returns:
    str: returns the subscription filter name by creating from the type of account and log group category.
    """
    try:
        subscription_filter_name = 'LogDestination'+type_of_acct+log_group_category
        return subscription_filter_name
    except Exception:
        logger.exception('An unexpected error occurred while trying to create subscription filter name.')

def putSubscription(log_group_search_name,subscription_filter_name,destination):
    """
    Returns the put subscription filter response API call.

    Parameters:
    log_group_search_name : Log group prefix for each log group category.
    subscription_filter_name: Created subscription filter using type of account and log group category.
    destination : Log destination ARN value

    Returns:
    str: Returns the put subscription filter response API call.
    """
    try:
        put_subscription_response = log_subscription_client.put_subscription_filter(
            logGroupName=log_group_search_name,
            filterName=subscription_filter_name,
            filterPattern='',
            destinationArn=destination
        )
        return put_subscription_response
    except Exception:
        logger.exception('An unexpected error occurred while trying to attach subscription filter to cloud watch log group based on the log group prefix.')

def getRegion():
    """
    Returns the AWS region of the authenticated user from boto3.

    Parameters:
    None

    Returns:
    str: Returns the Log Destination name which can be used in the creation of log destination ARN.
    """
    try:
        script_session = boto3.session.Session()
        script_region = script_session.region_name
        return script_region
    except Exception:
        logger.exception('An unexpected error occurred while trying to fetch the AWS region for log destination ARN creation.')

def createLogDestinationName(log_group_category,type_of_acct):
    """
    Returns the Log Destination name created using the standard naming convention.

    Parameters:
    log_group_category: Log Group Category which is initialized as global.
    type_of_acct : Account type passed an input to python script.

    Returns:
    str: Returns the region of the AWS account in which the script is run.
    """
    try:
        log_destination_name = 'CentralLogDestination'+log_group_category+type_of_acct
        return log_destination_name
    except Exception:
        logger.exception('An unexpected error occurred while trying to create log destination name as in Cloud formation template.')

def createLogdestinationArn(aws_region,aws_account_id,log_destination_name):
    """
    Returns the Log Destination name created using the standard naming convention.

    Parameters:
    aws_region: AWS region in which the script is run.
    aws_account_id: AWS account ID in which the script is run.
    log_destination_name: Log destination name created by the cloud formation in central logging account with naming convention.

    Returns:
    str: Returns the creates log destination ARN following the naming convention.
    """
    try:
        destination = 'arn:aws:logs:'+aws_region+':'+aws_account_id+':destination:'+log_destination_name
        return destination
    except Exception:
        logger.exception('An unexpected error occurred while trying to create log destination ARN value in core account.')


def getCentralLogAccountID():
    """
    Returns the Central logging account ID which is static value to custom python script.

    Parameters:
    None

    Returns:
    str: Returns the central logging account ID.
    """
    try:
        central_log_account_ID = '387385193794'
        return central_log_account_ID
    except Exception:
        logger.exception('An unexpected error occurred while trying to fetch central logging account ID.')

def getLogDestinationRegion():
    """
    Returns the AWS region in which Central logging account resources are created, which is third input parameter to custom python script.

    Parameters:
    None

    Returns:
    str: Returns the AWS region in which log destination is created in the central logging account.
    """
    try:
        log_destination_aws_region = sys.argv[2]
        return log_destination_aws_region
    except Exception:
        logger.exception('An unexpected error occurred while trying to fetch AWS region in which log destination is created in the central logging account.')

def main():

    log_group_category_count = 0
    count_log_groups = 0
    log_group_search_name = ''

    logger.info('## Fetching AWS AccountID in which custom script is run.')
    aws_account_id = getAccount()
    logger.info(aws_account_id)

    logger.info('## Fetching Type of Account.')
    type_of_acct = getAcctType()
    logger.info(type_of_acct)

    logger.info('## Fetching central logging account ID')
    central_log_account_ID = getCentralLogAccountID()
    logger.info(central_log_account_ID)

    logger.info('## Fetching Log Destination AWS region')
    log_destination_aws_region = getLogDestinationRegion()
    logger.info(log_destination_aws_region)

    if type_of_acct not in ('BKU', 'Backbase'):

        logger.info('## Type of account fetched is not a valid input. Account type should be BKU or Backbase, exiting the script...')
        sys.exit()

    else:

        if log_destination_aws_region not in ('us-east-2','us-east-1'):
            logger.info('## Log destination region in the central logging account can only be us-east-2 or us-east-1, exiting the script...')
            sys.exit()

        else:

            for log_group_category in log_group_categories:

                logger.info('## Fetching Log Group Search/prefix name.')
                log_group_search_name = getLogGroupName(type_of_acct,aws_account_id,log_group_category)
                logger.info(log_group_search_name)

                logger.info('## Appending Log group prefix for each log group category.')
                log_group_prefix = putLogGroupprefix(log_group_search_name)
                logger.info(format(log_group_prefix[log_group_category_count]))

                logger.info('## Fetching Log groups with the log group prefix for each log group category.')
                log_group_response = getLogGroups(log_group_search_name)

                list_log_groups = log_group_response['logGroups']

                # Incrementing the Log group category count
                log_group_category_count = log_group_category_count+1

                if len(list_log_groups) > 0:
                    logger.info('## Cloud Watch log groups with the search prefix <Type Of Account>-<Account ID>-<Log Category> exists.')

                    for log_group in list_log_groups:
                        #This condition is to make sure the prefix name matches the search name exactly
                        #To avoid filtering any cloud watch log group names which have a prefix <Type Of Account>-<Account ID>-<Log Category>.
                        if log_group['logGroupName'] == log_group_search_name:

                            logger.info('## Describing existing Subscription filters on cloud watch log group with log group prefix.')
                            subscription_filters_response = listSubscriptionFilters(log_group_search_name)
                            logger.info(subscription_filters_response)

                            # Iterate over results if there are any subscription filters (again, should not be multiple, but to follow the convention of the SDK)
                            for subscription_filter in subscription_filters_response['subscriptionFilters']:
                                # Retrieve the subscription filter name to use in the call to delete
                                filter_name = subscription_filter['filterName']

                                # Delete any subscriptions that are found on the log group
                                logger.info('## Deleting existing Subscription filters on cloud watch log group with log group prefix.')
                                delete_subscription_response = deleteSubscriptionFilters(log_group_search_name,filter_name)

                            #Add subscription to centralized logging to the log group with log_group_name
                            # Retrieve the destination for the subscription from the Parameter Store
                            ##log_destination_ssm_name = createLogDestination(type_of_acct,log_group_category)

                            #logger.info('## Fetching SSM API call response using the log destination name.')
                            ##logger.info(log_destination_response)

                            #Create log destination ARN
                            #Format of ARN arn:aws:logs:<AWS Region>:<AWS account ID>:destination:<Log destination name from CFN>

                            # 1. Get AWS Region
                            logger.info('## Fetching AWS region for log destination ARN creation')
                            aws_region = getRegion()
                            logger.info(aws_region)
                            # 2. Get AWS account ID. Already fetched.
                            # 3. Log Destination name from CFN.
                            # Naming convention for Log destination name CentralLogDestination<log group category><type of account>
                            logger.info('## Creating log destination name using the naming convention.')
                            log_destination_name = createLogDestinationName(log_group_category,type_of_acct)
                            logger.info(log_destination_name)

                            # 4. Get Log destination ARN
                            logger.info('## Creating log destination ARN.')
                            destination = createLogdestinationArn(log_destination_aws_region,central_log_account_ID,log_destination_name)
                            logger.info(destination)

                            # Error if there is no destination, otherwise extract destination id from response
                            #if not log_destination_response:
                            #        'Cannot locate central logging destination, put_subscription_filter failed')
                            #else:
                            #    destination = getLogDestinationArn(log_destination_response)
                            #    logger.info(destination)

                            # Create subscription filter name
                            logger.info('## Creating Subscription filter name.')
                            subscription_filter_name = createSubscriptionFilterName(type_of_acct,log_group_category)
                            logger.info(subscription_filter_name)

                            # Put the new subscription with the destination onto the log group
                            logger.info('## Attaching new subscription filter to central logging destination.')
                            put_subscription_response = putSubscription(log_group_search_name,subscription_filter_name,destination)
                            logger.info(put_subscription_response)
                        else:
                            logger.info('## Either Cloud Watch Log groups for the specified log group category do not exist or log groups are not following the naming convention.')
                            logger.info('## Cloud Watch log groups should have <Type Of Account>-<Account ID>-<Log Category> naming convention.')

                else:
                    logger.info('## Either Cloud Watch Log groups for the specified log group category do not exist or log groups are not following the naming convention.')
                    logger.info('## Cloud Watch log groups should have <Type Of Account>-<Account ID>-<Log Category> naming convention.')


if __name__ == "__main__":
    main()

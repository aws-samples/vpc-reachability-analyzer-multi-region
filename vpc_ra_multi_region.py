import boto3
import botocore
import pprint
import json
import argparse
import re

pp = pprint.PrettyPrinter(compact=True)

MAX_PATHS=4

WAITER_ID = 'NetworkInsightsAnalysisSucceeded'
model = botocore.waiter.WaiterModel(
{
    'version': 2,
    'waiters': {
        WAITER_ID: {
            'delay': 30,
            'maxAttempts': 10,
            'operation': 'DescribeNetworkInsightsAnalyses',
            'acceptors': [
                {
                    'expected': 'succeeded',
                    'matcher': 'pathAll',
                    'state': 'success',
                    'argument': "NetworkInsightsAnalyses[].Status"
                },
                {
                    "expected": "failed",
                    "matcher": "pathAny",
                    "state": "failure",
                    "argument": "NetworkInsightsAnalyses[].Status"
                }
            ]
        }
    }
})


# gets a list of TGW peering attachments that are in 'available' state
def get_tgw_peering_attachments(region):
    tgw_list = []
    ec2 = boto3.client('ec2', region_name = region)
    tgw_attachments_paginator = ec2.get_paginator('describe_transit_gateway_attachments')
    tgw_attachments_iterator = tgw_attachments_paginator.paginate(
        Filters = [
            {
                'Name': 'resource-type',
                'Values': ['peering']
            },
            {
                'Name': 'state',
                'Values': ['available']
            }
        ]
    )

    for tgw_attachments_page in tgw_attachments_iterator:
        for tgw_attachment in tgw_attachments_page['TransitGatewayAttachments']:
            tgw_list.append(tgw_attachment)

    return tgw_list

def analyze_path(region, source, source_ip, destination, destination_ip, destination_port, protocol, name):
    # create a path from source to destination in region, with tag 'name'
    # and wait for the analysis to complete
    ec2 = boto3.client('ec2', region_name = region)

    path = ec2.create_network_insights_path(
        Source = source,
        Destination = destination,
        SourceIp=source_ip,
        DestinationIp = destination_ip,
        Protocol = protocol,
        DestinationPort=destination_port,
        TagSpecifications = [
            {
                'ResourceType': 'network-insights-path',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': name
                    }
                ]
            }
        ]
    )
    analysis = ec2.start_network_insights_analysis(
        NetworkInsightsPathId = path['NetworkInsightsPath']['NetworkInsightsPathId']
    )
    #pp.pprint(analysis)
    analysis_id = analysis['NetworkInsightsAnalysis']['NetworkInsightsAnalysisId']

    waiter = botocore.waiter.create_waiter_with_client(WAITER_ID, model, ec2)
    waiter.wait(
        NetworkInsightsAnalysisIds=[
            analysis_id
        ]
    )

    resp = ec2.describe_network_insights_analyses(
        NetworkInsightsAnalysisIds = [
            analysis_id
        ]
    )
    #pp.pprint(resp)
    return resp


def analyze_peering_attachment_pair(source_region, source_resource, source_ip, source_attachment, destination_region, destination_resource, destination_ip, destination_port, protocol, destination_attachment):
    # In source region: analyze path from source_resource to source attachment
    src = source_resource
    dst = source_attachment['TransitGatewayAttachmentId']
    r1 = analyze_path(source_region, src, source_ip, dst, destination_ip, destination_port, protocol, f"From {src} to {destination_region} via {dst}")

    # In destination region: analyze path from destination attachment to destination_resource
    src = destination_attachment['TransitGatewayAttachmentId']
    dst = destination_resource
    r2 = analyze_path(destination_region, src, source_ip, dst, destination_ip, destination_port, protocol, f"From {source_region} to {dst} via {src}")

    return [r1, r2]


def analyze(source_region, source_resource, source_ip, destination_region, destination_resource, destination_ip, destination_port, protocol):
    # get peering attachments from both regions
    source_tgw_attachments = get_tgw_peering_attachments(source_region)
    destination_tgw_attachments = get_tgw_peering_attachments(destination_region)

    # identify peering attachments pairs that go from source region to destination region
    source_to_destination_region_attachments = []

    for source in source_tgw_attachments:
        src_tgw = source['TransitGatewayId']
        dst_tgw = source['ResourceId']
        for destination in destination_tgw_attachments:
            if(dst_tgw == destination['TransitGatewayId']):
                # we found a peering attachment pair from source to destination region
                source_to_destination_region_attachments.append([
                    source, destination
                ])

    num_paths = len(source_to_destination_region_attachments)

    if(num_paths > MAX_PATHS):
        # number of possible paths exceeds the maximum allowed, fail
        raise ValueError(f"Found {num_paths} possible paths from the source region to destination region that is higher than the maximum allowed paths {MAX_PATHS}. Please check your network configuration or increase the maximum allowed paths using the --max-paths argument")

    #pp.pprint(source_to_destination_region_attachments)

    e2e_path_components = []
    successful_pair = None
    unsuccessful_pairs = []

    # analyze each peering attachment pair
    for pair in source_to_destination_region_attachments:
        results = analyze_peering_attachment_pair(source_region, source_resource, source_ip, pair[0], destination_region, destination_resource, destination_ip, destination_port, protocol, pair[1])

        if(results[0]['NetworkInsightsAnalyses'][0]['NetworkPathFound'] and
        results[1]['NetworkInsightsAnalyses'][0]['NetworkPathFound']):
            # A complete path was found, combine the ForwardPathComponents
            successful_pair = results
            # Add a field representing resource region in each path component
            for c in results[0]['NetworkInsightsAnalyses'][0]['ForwardPathComponents']:
                c['ResourceRegion'] = source_region
                e2e_path_components.append(c)
            seq_start = len(e2e_path_components)

            # Add the second list of ForwardPathComponents with updated sequence numbers
            for c in results[1]['NetworkInsightsAnalyses'][0]['ForwardPathComponents']:
                c['ResourceRegion'] = destination_region
                c['SequenceNumber'] += seq_start
                e2e_path_components.append(c)
        else:
            unsuccessful_pairs.append(results)

    #print(json.dumps(e2e_path_components))

    return {
        'SuccessfulPair': successful_pair,
        'UnsuccessfulPairs': unsuccessful_pairs
    }

def create_response(pair, source_region, destination_region):
    if(pair == None):
        return None
    else:
        return {
            'SourceNetworkInsightsAnalysisArn': pair[0]['NetworkInsightsAnalyses'][0]['NetworkInsightsAnalysisArn'],
            'SourceNetworkInsightsAnalysisURL':
                f"https://{source_region}.console.aws.amazon.com/networkinsights/home?region={source_region}#NetworkPathAnalysis:analysisId={pair[0]['NetworkInsightsAnalyses'][0]['NetworkInsightsAnalysisId']}",
                # console deep-link for NIA example: https://us-east-2.console.aws.amazon.com/networkinsights/home?region=us-east-2#NetworkPathAnalysis:analysisId=nia-01b8f48c27ca65fa2
            'SourceNetworkInsightsPathId': pair[0]['NetworkInsightsAnalyses'][0]['NetworkInsightsPathId'],

            'DestinationNetworkInsightsAnalysisArn': pair[1]['NetworkInsightsAnalyses'][0]['NetworkInsightsAnalysisArn'],
            'DestinationNetworkInsightsAnalysisURL':
                f"https://{destination_region}.console.aws.amazon.com/networkinsights/home?region={destination_region}#NetworkPathAnalysis:analysisId={pair[1]['NetworkInsightsAnalyses'][0]['NetworkInsightsAnalysisId']}",
            'DestinationNetworkInsightsPathId': pair[1]['NetworkInsightsAnalyses'][0]['NetworkInsightsPathId'],
        }


def help_exit(parser, msg):
    print(msg)
    #parser.print_help()
    exit(-1)

# Usage:
# python3 vpc_ra_multi_region.py --destination-port 22 --source-ip '10.100.7.248' --destination-ip '10.200.11.8' --source-resource arn:aws:ec2:us-east-2:218646657273:instance/i-04e7cb43e225e1334 --destination-resource arn:aws:ec2:us-west-2:791373089996:instance/i-0f49e55817a0b8ada --protocol 'tcp' --max-paths 2

parser = argparse.ArgumentParser()

parser.add_argument('--source-resource', metavar='SOURCE_RESOURCE_ARN', help='Source resource ARN', required=True)
parser.add_argument('--source-ip', help='Source IPv4 address', required=True)
parser.add_argument('--destination-resource', metavar='DESTINATION_RESOURCE_ARN', help='Destination resource ARN', required=True)
parser.add_argument('--destination-ip', help='Destination IPv4 address', required=True)
parser.add_argument('--destination-port', help='Destination port', type=int, required=True)
parser.add_argument('--protocol', help='Protocol: udp or tcp (defaults to tcp)', choices=['udp', 'tcp'], default='tcp')
parser.add_argument('--max-paths', help='Maximum number of paths between the two regions to evaluate (defaults to 4)', type=int, default=4)

args = parser.parse_args()

# ARN regex
# arn:aws:ec2:us-east-1:123456789012:instance/i-012abcd34efghi56
ARN_REGEX = ''.join(['arn:',
             '([^:]+):', # 1 partition
             '([^:]+):', # 2 service
             '([^:]+):', # 3 region
             '([^:]+):', # 4 account_id
             '(.*)' # the rest
])

arn_regex = re.compile(ARN_REGEX)
ipv4_regex = re.compile('^([0-9]{1,3}.){3}[0-9]{1,3}$')

# validate arguments
if(args.source_resource and not arn_regex.match(args.source_resource)):
   help_exit(parser, 'source-resource must be a valid AWS ARN')

if(args.destination_resource and not arn_regex.match(args.destination_resource)):
   help_exit(parser, 'destination-resource must be a valid AWS ARN')

if(args.source_ip and not ipv4_regex.match(args.source_ip)):
    help_exit(parser, 'source-ip must be a valid IPv4 address')

if(args.destination_ip and not ipv4_regex.match(args.destination_ip)):
    help_exit(parser, 'destination-ip must be a valid IPv4 address')

if(args.destination_port < 0 or args.destination_port > 65535):
    help_exit(parser, 'destination-port must be between 0 and 65535')

if(args.max_paths <= 0):
    help_exit(parser, 'max-paths must be greater than 0')

MAX_PATHS=args.max_paths

m = arn_regex.match(args.source_resource)
source_partition = m.group(1)
source_region = m.group(3)

m = arn_regex.match(args.destination_resource)
destination_partition = m.group(1)
destination_region = m.group(3)

if(source_region == destination_region):
    help_exit(parser, "source-resource and destination-resource are in the same region: you don't need this script to analyze reachability, you can directly execute a Reachability Analyzer analysis")

if(source_partition != destination_partition):
    help_exit(parser, "source-resource and destination-resource must be in the same AWS partition")


pair_results = analyze(source_region, args.source_resource, args.source_ip, destination_region, args.destination_resource, args.destination_ip, args.destination_port, args.protocol)

#pp.pprint(pair_results)
response = {}

response['SuccessfulPair'] = create_response(pair_results['SuccessfulPair'], source_region, destination_region)
response['UnsuccessfulPairs'] = []

for pair in pair_results['UnsuccessfulPairs']:
    response['UnsuccessfulPairs'].append(create_response(pair, source_region, destination_region))

print(json.dumps(response))

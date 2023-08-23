## Using VPC Reachability Analyzer for your multi region deployment

This repo shows how you can use VPC Reachability Analyzer (VPC RA) to trace networking paths across multiple regions.

### When to use this solution
This solution works when you use Transit Gateway (TGW) peering to provide connectivity across multiple AWS Regions.

### How this solution works
This solution leverages VPC Reachability Analyzer's native capabilities, and creates multiple regional VPC RA scopes to trace network connectivity. If you use this solution to trace the networking path between the two EC2 instances, this solution will first determine that there are two paths between the two AWS Regions: Path-1 and Path-2.

After discovering the paths, this solution will create a pair of regional VPC RA analyses for each path. Figure-1 shows the regional VPC RA analyses for Path-1:
Analysis 1a in source Region: source resource (user specified) is the source, and TGW-ohio's cross region peering attachment is the destination
Analysis 1b in destination Region: TGW-oregon's cross region peering attachment is the source, and the destination resource (user specified) is the destination

![Figure-1 Sample Architecture](architecture.png)

The script concludes that there is a networking path between the source and the destination if both VPC RA analyses for a path are successful. The script records this VPC RA analyses pair as a 'SuccessfulPair'
If any one (or both) of the VPC RA analyses for a path are unsuccessful, the script treats that as an 'UnsuccessfulPair'.

#### PreRequisites
- This script makes API calls to AWS, and requires IAM privileges to discover networking constructs and to create/execute VPC RA analyses. It's ideal to execute this script from the central networking/infra AWS account
- If using in a multi account scenario, set up VPC RA delegated admin account. Check out the [VPC RA multi-account blog post](https://aws.amazon.com/blogs/networking-and-content-delivery/visualize-and-diagnose-network-reachability-across-aws-accounts-using-reachability-analyzer/) for details
- Install python3 on the machine where you'll run this script

### How to use
Use `aws configure` to ensure you have the correct IAM privileges. After that, clone the repo:

```
git clone https://github.com/aws-samples/vpc-reachability-analyzer-multi-region
```

Parameters used by the script:

- **source-ip:** IP address of the source resource
- **source-resource:** full ARN of the source resource
- **destination-ip:** IP address of the destination resource
- **destination-resource:** full ARN of the destination resource
- **destination-port:** destination port used to evaluate connectivity
- **protocol:** TCP or UDP (defaults to TCP)
- **max-paths:** in case there are many different paths between the source and destination Regions, this script can take a long time to finish execution. Use this parameter to limit the number of paths that should be considered between the two AWS Regions. In the architecture shown below, there are 2 separate paths between the two AWS Regions.

```
python3 vpc_ra_multi_region.py --destination-port <destination-port> \
--source-ip <source-IP> \
--destination-ip <destination-IP> \
--source-resource <source-resource-ARN> \
--destination-resource <destination-resource-ARN> \
--protocol <TCP-or-UDP> \
--max-paths 2
```

Example:
```
python3 vpc_ra_multi_region.py --destination-port 22 --source-ip '10.100.7.248' --destination-ip '10.200.11.8' --source-resource arn:aws:ec2:us-east-2:1234567890:instance/<instance-ID> --destination-resource arn:aws:ec2:us-west-2:987654321:instance/<instance-ID> --protocol 'tcp' --max-paths 2
```

### Reading the output
The script returns details of SuccessfulPair and UnsuccessfulPair in the JSON output. You can click on the URLs to get more details about the VPC RA analyses on the console.

Sample output:
```
{"SuccessfulPair": {"SourceNetworkInsightsAnalysisArn": "arn:aws:ec2:us-east-2:490797190003:network-insights-analysis/nia-0d650e7796f9805ff", "SourceNetworkInsightsAnalysisURL": "https://us-east-2.console.aws.amazon.com/networkinsights/home?region=us-east-2#NetworkPathAnalysis:analysisId=nia-0d650e7796f9805ff", "SourceNetworkInsightsPathId": "nip-0ddc84bb0e18158dd", "DestinationNetworkInsightsAnalysisArn": "arn:aws:ec2:us-west-2:490797190003:network-insights-analysis/nia-064e9f8277492bf79", "DestinationNetworkInsightsAnalysisURL": "https://us-west-2.console.aws.amazon.com/networkinsights/home?region=us-west-2#NetworkPathAnalysis:analysisId=nia-064e9f8277492bf79", "DestinationNetworkInsightsPathId": "nip-04cc847cbf063459d"}, "UnsuccessfulPairs": [{"SourceNetworkInsightsAnalysisArn": "arn:aws:ec2:us-east-2:490797190003:network-insights-analysis/nia-0c5f01f2c8e9be5ca", "SourceNetworkInsightsAnalysisURL": "https://us-east-2.console.aws.amazon.com/networkinsights/home?region=us-east-2#NetworkPathAnalysis:analysisId=nia-0c5f01f2c8e9be5ca", "SourceNetworkInsightsPathId": "nip-0ab03b2dacc6cdb24", "DestinationNetworkInsightsAnalysisArn": "arn:aws:ec2:us-west-2:490797190003:network-insights-analysis/nia-04b1ee1c83fdafac0", "DestinationNetworkInsightsAnalysisURL": "https://us-west-2.console.aws.amazon.com/networkinsights/home?region=us-west-2#NetworkPathAnalysis:analysisId=nia-04b1ee1c83fdafac0", "DestinationNetworkInsightsPathId": "nip-0f947efb3ef8d3b85"}]}
```

### Pricing
VPC Reachability Analyzer has a per analysis price of $0.10. Please check out [VPC pricing page](https://aws.amazon.com/vpc/pricing/) for details.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

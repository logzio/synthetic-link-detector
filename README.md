# Synthetic Link Detector

This project allows you to detect broken links in a web page, and to get additional data about the links.


## Getting Started

To deploy this project, click the button that matches the region you wish to deploy your Stack to:

| Region           | Deployment                                                                                                                                                                                                                                                                                                                                                       |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `us-east-1`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-us-east-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)           | 
| `us-east-2`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-us-east-2.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)           | 
| `us-west-1`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-west-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-us-west-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)           | 
| `us-west-2`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-us-west-2.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)           | 
| `eu-central-1`   | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-central-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-central-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)     | 
| `eu-north-1`     | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-north-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-north-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)         | 
| `eu-west-1`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-west-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)           | 
| `eu-west-2`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-west-2.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)           | 
| `eu-west-3`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-3#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-west-3.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)           | 
| `sa-east-1`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=sa-east-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-sa-east-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)           | 
| `ap-northeast-1` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-northeast-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector) | 
| `ap-northeast-2` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-northeast-2.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector) | 
| `ap-northeast-3` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-3#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-northeast-3.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector) | 
| `ap-south-1`     | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-south-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-south-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)         | 
| `ap-southeast-1` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-southeast-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-southeast-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector) | 
| `ap-southeast-2` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-southeast-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-southeast-2.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector) | 
| `ca-central-1`   | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ca-central-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-ca-central-1.s3.amazonaws.com/synthetic-link-detector/0.0.1/sam-template.yaml&stackName=logzio-synthetic-link-detector)     |

### 1. Specify stack details

Specify the stack details as per the table below, check the checkboxes and select **Create stack**.

| Parameter                    | Description                                                                                                                         | Required/Default                    |
|------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| `logzioToken`                | Replace `<<SHIPPING-TOKEN>>` with the [token](https://app.logz.io/#/dashboard/settings/general) of the account you want to ship to. | **Required**                        |
| `logzioListener`             | Listener host, and port (for example, `https://<<LISTENER-HOST>>:8071`).                                                            | **Required**                        |
| `url`                        | Full URL of the web page you wish to monitor. For example - `https://logz.io`                                                       | **Required**                        |
| `functionInvocationInterval` | The scheduling expression that determines how often the Lambda function runs                                                        | Default: `rate(1 days)`             |
| `logzioCustomFields`         | Enrich the data with custom fields, formatted as `key1=value1,key2=value2`                                                          | -                                   |
| `functionTimeout`            | Timeout for your Lambda function, in seconds                                                                                        | Default: `60`                       |
| `functionMemorySize`         | Memory size (in MB) for your Lambda function                                                                                        | Default: `512`                      |
| `logzioType`                 | The log type you'll use with this Lambda.                                                                                           | Default: `synthetic-links-detector` |

### 2. Send logs

Give the stack a few minutes to be deployed.

Once the stack will be created, the function will run one time and send data, then it will run in the rate the you've defined.

## Acknowledgment

This project is based on [httpstat repo](https://github.com/davecheney/httpstat).

### Changelog:

- **0.0.1**: Initial release.
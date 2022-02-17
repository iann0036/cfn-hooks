# Generic::SecretsProtection::Hook

This resource protects against accidental secrets exposure by observing every property of every AWS resource type.

## Getting Started

After [activating](https://aws.amazon.com/blogs/mt/proactively-keep-resources-secure-and-compliant-with-aws-cloudformation-hooks/) the hook in the registry, you should apply configuration to enforce the failure mode. In the hook properties, click the **Configuration** tab, then the **Edit configuration** button, set a configuration alias (for example "default"), and add the configuration JSON.

You may use the following configuration JSON to start using the hook right away with defaults:

```
{
    "CloudFormationConfiguration": {
        "HookConfiguration": {
            "TargetStacks": "ALL",
            "FailureMode": "FAIL",
            "Properties": {}
        }
    }
}
```

## Getting Failure Information

To view failure information, you should first click the cog in the CloudFormation stack view, and ensure the `Hook invocations` column is present.

![Screenshot](https://raw.githubusercontent.com/iann0036/iann0036/master/static/hooks1.png)

If a hook fails, the detailed error response will be in the stack event immediately before the failure:

![Screenshot](https://raw.githubusercontent.com/iann0036/iann0036/master/static/hooks2.png)

## Extra Configuration Properties

The `Configuration` property takes in a list of rules with a `Description` of the rules and a `Regex` escaped as a JSON string. To escape your string, I recommend [this site](https://www.freeformatter.com/json-escape.html). For example, a full configuration might look like:

```
{
    "CloudFormationConfiguration": {
        "HookConfiguration": {
            "TargetStacks": "ALL",
            "FailureMode": "FAIL",
            "Properties": {
                "Rules": [
                    {
                        "Description": "GitLab Personal Access Token",
                        "Regex": "glpat-[0-9a-zA-Z\\-]{20}"
                    },
                    {
                        "Description": "AWS Access Token",
                        "Regex": "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
                    }
                ]
            }
        }
    }
}
```

If you do not provide a Configuration, a standard [default ruleset](https://github.com/iann0036/cfn-hooks/blob/main/Generic-SecretsProtection-Hook/src/generic_secretsprotection_hook/handlers.py#L62) will be used.

The `Exceptions` property may be used to provide a comma-separated list of properties to not test for the presence of secrets. For example, the configuration may look like:

```
{
    "CloudFormationConfiguration": {
        "HookConfiguration": {
            "TargetStacks": "ALL",
            "FailureMode": "FAIL",
            "Properties": {
                "Exceptions": [
                    "AWS::EC2::Instance.UserData",
                    "AWS::S3::Bucket.Tags[].Value",
                    "AWS::Lambda::Function.Environment.Variables.__KEY"
                ]
            }
        }
    }
}
```

## Acknowledgements

Thanks to the [GitLeaks](https://github.com/zricethezav/gitleaks) project for inspiration and the default ruleset.

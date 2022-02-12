# Generic::SecretsProtection::Hook

This resource protects against accidental secrets exposure by observing every property of every AWS resource type.

## Configuration

The `Configuration` property takes in a [GitLeaks](https://github.com/zricethezav/gitleaks) configuration TOML file, escaped as a JSON string. To escape your string, I recommend [this site](https://www.freeformatter.com/json-escape.html). For example, a full configuration might look like:

```
{
    "CloudFormationConfiguration": {
        "HookConfiguration": {
            "TargetStacks": "ALL",
            "FailureMode": "FAIL",
            "Properties": {
                "Configuration": "[[rules]]\r\nid = \"gitlab-pat\"\r\ndescription = \"GitLab Personal Access Token\"\r\nregex = '''glpat-[0-9a-zA-Z\\-]{20}'''\r\n\r\n[[rules]]\r\nid = \"aws-access-token\"\r\ndescription = \"AWS\"\r\nregex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''"
            }
        }
    }
}
```

Currently, the only supported features are `[[rules]].id` and `[[rules]].regex`. Regexes currently may need to be altered to match the Python `re` match structure. This will be adjusted in a future release.

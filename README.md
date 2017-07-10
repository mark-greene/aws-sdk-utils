# aws-sdk-utils

AWS Utility Scripts using the Ruby AWS SDK

By default, each script uses `report.yml`.  This can be overridden on the command line
### ec2-report
Reports info about your EC2 instances including Tags (compliance)
```
ruby ec2-report   # default report.yml config
ruby ec2-report conf/sandbox.yml
```

### rds-report
Reports info about your RDS instances including Tags (compliance)
```
ruby rds-report   # default report.yml config
ruby rds-report conf/sandbox.yml
```

### resource-report
Reports info about your AWS resources including Tags (compliance)
```
ruby resource-report  # default report.yml config
ruby resource-report fix  # Make Tags compliant
ruby rds-report conf/sandbox.yml fix  # Apply sandbox.yml config
```

### Notes
`report.yml` specifies the AWS cli profiles to use to access your environment, the regions to explore
and the tags to check.  `resource-report fix` will apply the Tags specified by VPC.

`tagger.rb` is deprecated.  Fog-Aws was used to set Tags until the full transition to the Ruby SDK

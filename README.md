# SPF-FLATTENER

This tool flattens the SPF record for a given domain to avoid reaching the 10 DNS lookup cap.

## Flags
| Flag | Required? | Type | Default | Description |
|------| ----------| --------| -----|-------------|
| domain | *required* | string | | root domain to set SPF record for |
| initialSPF | *optional* | string | "" | initial SPF record to flatten* |
| verbose | *optional* | bool | false | if true, print extra debug lines |
| dryrun | *optional* | bool | true | if false, update existing SPF record with flattened SPF |
| warn | *optional* | bool | true | if true, compares initial and flattened SPF, warning when different |
| url | *optional*** | string | "" | url to PATCH updated SPF record |
| authEmail | *optional*** | string | "" | X-Auth-Email header value |
| authKey | *optiona*** | string | "" | X-Auth-Key header value |

*if not provided, will lookup and use existing SPF record for domain

**unless dryrun is false, then required

## Example use cases

**Base case**: one-time flatten tool, just want to output flattened record:
```
go run main.go --domain <domain> --warn false
```

**Dynamic update case**: update SPF tool that acts without intervention. For example, a cron job that runs:
```
go run main.go --domain <domain> --initialSPF "<spfRecord>" --dryrun false --warn false --url "<url>" --authEmail "<email>" --authKey "<key>"
```

**Dynamic warning case**: recurring check SPF tool that alerts/warns on change. For example, a cron job that runs:
```
go run main.go --domain <domain> --intialSPF="<spfRecord>" 
```
Then once someone checks/approves of change, run once:
```
go run main.go --domain <domain> --initialSPF "<spfRecord>" --dryrun false --warn false --url "<url>" --authEmail "<email>" --authKey "<key>"

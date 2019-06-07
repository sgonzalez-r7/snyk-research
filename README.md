# Snyk research

## [API - snyk.apib](https://github.com/sgonzalez-r7/snyk-research/blob/master/snyk.apib.md)

## Setup
- `cd $GOPATH/src`
- `git clone git@github.com:sgonzalez-r7/snyk-research.git`
- `cd snyk-research`
- `go get ./...`
- `cp .env.example .env`
- Add your Snyk API Key to `.env`

## Running

### get
```
go run get.go [endpoint]

go run get.go
   => GET https://snyk.io/api/v1

go run get.go org/:orgID/projects
   => GET https://snyk.io/api/v1/org/:orgId/projects
```

### get-latest-issue-counts
```
go run get-latest-issue-counts.go <:orgId>
```

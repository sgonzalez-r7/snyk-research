FORMAT: 1A
HOST: https://snyk.io/api/v1

# Snyk API

The Snyk API is available to customers on [paid plans](https://snyk.io/plans) and allows you to programatically integrate with Snyk.



## API vs CLI vs Snyk Integration
The API detailed below has the ability to test a package for issues, as they are defined by Snyk. It is important to note that for many package managers, using this API will be less accurate than running the [Snyk CLI](https://snyk.io/docs/using-snyk) as part of your build pipe, or just using it locally on your package. The reason for this is that more than one package version fit the requirements given in manifest files. Running the CLI locally tests the actual deployed code, and has an accurate snapshot of the dependency versions in use, while the API can only infer it, with inferior accuracy. It should be noted that the Snyk CLI has the ability to output machine-readable JSON output (with the `--json` flag to `snyk test`).

A third option, is to allow Snyk access to your development flow via the existing [Snyk integrations](https://snyk.io/docs/). The advantage to this approach is having Snyk monitor every new pull request, and suggest fixes by opening new pull requests. This can be achieved either by integrating Snyk directly to your source code management (SCM) tool, or via a broker to allow greater security and auditability.

If those are not viable options, this API is your best choice.

## API Url
The base URL for all API endpoints is https://snyk.io/api/v1/

## Authorization
To use this API, you must get your token from Snyk. It can be seen on https://snyk.io/account/ after you register with Snyk and login.

The token should be supplied in an `Authorization` header with the token, preceded by `token`:


```http
Authorization: token API_KEY
```

Otherwise, a 401 "Unauthorized" response will be returned.
```http
HTTP/1.1 401 Unauthorized

        {
            "code": 401,
            "error": "Not authorised",
            "message": "Not authorised"
        }
```


## Overview and Entities
The API is a REST API. It has the following entities:

### Test Result
The test result is the object returned from the API giving the results of testing a package for issues. It has the following fields:

| Property        | Type    | Description                                           | Example                                                         |
|----------------:|---------|-------------------------------------------------------|-----------------------------------------------------------------|
| ok              | boolean | Does this package have one or more issues?             | false                                                           |
| issues          | object  | The issues found. See below for details.              | See below                                                       |
| dependencyCount | number  | The number of dependencies the package has.           | 9                                                               |
| org             | object  | The organisation this test was carried out for.       | {"name": "anOrg", "id": "5d7013d9-2a57-4c89-993c-0304d960193c"} |
| licensesPolicy  | object  | The organisation's licenses policy used for this test | See in the examples                                             |
| packageManager  | string  | The package manager for this package                  | "maven"                                                         |
|                 |         |                                                       |                                                                 |


### Issue
An issue is either a vulnerability or a license issue, according to the organisation's policy. It has the following fields:

| Property       | Type          | Description                                                                                                                | Example                                |
|---------------:|---------------|----------------------------------------------------------------------------------------------------------------------------|----------------------------------------|
| id             | string        | The issue ID                                                                                                               | "SNYK-JS-BACKBONE-10054"               |
| url            | string        | A link to the issue details on snyk.io                                                                                     | "https://snyk.io/vuln/SNYK-JS-BACKBONE-10054 |
| title          | string        | The issue title                                                                                                            | "Cross Site Scripting"                 |
| type           | string        | The issue type: "license" or "vulnerability".                                                                              | "license"                              |
| paths          | array         | The paths to the dependencies which have an issue, and their corresponding upgrade path (if an upgrade is available). [More information about from and upgrade paths](#introduction/overview-and-entities/from-and-upgrade-paths) | [<br>&nbsp;&nbsp;{<br>&nbsp;&nbsp;&nbsp;&nbsp;"from": ["a@1.0.0", "b@4.8.1"],<br>&nbsp;&nbsp;&nbsp;&nbsp;"upgrade": [false, "b@4.8.2"]<br>&nbsp;&nbsp;}<br>] |
| package        | string        | The package identifier according to its package manager                                                                    | "backbone", "org.apache.flex.blazeds:blazeds"|
| version        | string        | The package version this issue is applicable to.                                                                           | "0.4.0"                                |
| severity       | string        | The Snyk defined severity level: "high", "medium" or "low".                                                                | "high"                                 |
| language       | string        | The package's programming language                                                                                         | "js"                                   |
| packageManager | string        | The package manager                                                                                                        | "npm"                                  |
| semver         | array[string] OR map[string]array[string] | One or more [semver](https://semver.org) ranges this issue is applcable to. The format varies according to package manager. | ["<0.5.0, >=0.4.0", "<0.3.8, >=0.3.6"] OR { "vulnerable": ["[2.0.0, 3.0.0)"], "unaffected": ["[1, 2)", "[3, )"] } |


### Vulnerability
A vulnerability in a package. In addition to all the fields present in an issue, a vulnerability also has these fields:

 Property        | Type    | Description                                                                                                                                                                                                                      | Example                                        |
----------------:|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------|
 publicationTime | Date    | The vulnerability publication time                                                                                                                                                                                               | "2016-02-11T07:16:18.857Z"                     |
 disclosureTime  | Date    | The time this vulnerability was originally disclosed to the package maintaners                                                                                                                                                   | "2016-02-11T07:16:18.857Z"                     |
 isUpgradable    | boolean | Is this vulnerability fixable by upgrading a dependency?                                                                                                                                                                         | true                                           |
 description     | string  | The detailed description of the vulnerability, why and how it is exploitable. Provided in markdown format. | "## Overview\n[`org.apache.logging.log4j:log4j-core`](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22log4j-core%22)\nIn Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.\n\n# Details\nSerialization is a process of converting an object into a sequence of bytes which can be persisted to a disk or database or can be sent through streams. The reverse process of creating object from sequence of bytes is called deserialization. Serialization is commonly used for communication (sharing objects between multiple hosts) and persistence (store the object state in a file or a database). It is an integral part of popular protocols like _Remote Method Invocation (RMI)_, _Java Management Extension (JMX)_, _Java Messaging System (JMS)_, _Action Message Format (AMF)_, _Java Server Faces (JSF) ViewState_, etc.\n\n_Deserialization of untrusted data_ ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)), is when the application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, letting the attacker to control the state or the flow of the execution. \n\nJava deserialization issues have been known for years. However, interest in the issue intensified greatly in 2015, when classes that could be abused to achieve remote code execution were found in a [popular library (Apache Commons Collection)](https://snyk.io/vuln/SNYK-JAVA-COMMONSCOLLECTIONS-30078). These classes were used in zero-days affecting IBM WebSphere, Oracle WebLogic and many other products.\n\nAn attacker just needs to identify a piece of software that has both a vulnerable class on its path, and performs deserialization on untrusted data. Then all they need to do is send the payload into the deserializer, getting the command executed.\n\n> Developers put too much trust in Java Object Serialization. Some even de-serialize objects pre-authentication. When deserializing an Object in Java you typically cast it to an expected type, and therefore Java's strict type system will ensure you only get valid object trees. Unfortunately, by the time the type checking happens, platform code has already created and executed significant logic. So, before the final type is checked a lot of code is executed from the readObject() methods of various objects, all of which is out of the developer's control. By combining the readObject() methods of various classes which are available on the classpath of the vulnerable application an attacker can execute functions (including calling Runtime.exec() to execute local OS commands).\n- Apache Blog\n\n\n## References\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5645)\n- [Jira Issue](https://issues.apache.org/jira/browse/LOG4J2-1863)\n" |
 isPatchable     | boolean | Is this vulnerability fixable by using a Snyk supplied patch?                                                                                                                                                                    | true                                           |
 identifiers     | object  | Additional vulnerability identifiers                                                                                                                                                                                             | {"CWE": [], "CVE": ["CVE-2016-2402]}           |
 credit          | string  | The reporter of the vulnerability                                                                                                                                                                                                | "Snyk Security Team"                           |
 CVSSv3          | string  | Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics of a vulnerability, and produce a numerical score reflecting its severity, as well as a textual representation of that score. | "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" |
 cvssScore       | number  | CVSS Score                                                                                                                                                                                                                       | 5.3                                            |
 patches         | array   | Patches to fix this issue, by snyk                                                                                                                                                                                               | see "Patch" below.                             |
 upgradePath     | object  | The path to upgrade this issue, if applicable                                                                                                                                                                                    | see below                                      |
 isPatched       | boolean | Is this vulnerability patched?                                                                                                                                                                                                   | false                                          |


#### Patch
A patch is an object like this one:
```json
{
  "urls": [
    "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/backbone/20110701/backbone_20110701_0_0_0cdc525961d3fa98e810ffae6bcc8e3838e36d93.patch"
  ],
  "version": "<0.5.0 >=0.3.3",
  "modificationTime": "2015-11-06T02:09:36.180Z",
  "comments": [
    "https://github.com/jashkenas/backbone/commit/0cdc525961d3fa98e810ffae6bcc8e3838e36d93.patch"
  ],
  "id": "patch:npm:backbone:20110701:0"
}
```

### From and upgrade paths
Both from and upgrade paths are arrays, where each item within the array is a package `name@version`.

Take the following `from` path:
```
[
  "my-project@1.0.0",
  "actionpack@4.2.5",
  "rack@1.6.4"
]
```
Assuming this was returned as a result of a test, then we know:
- The package that was tested was `my-project@1.0.0`
- The dependency with an issue was included in the tested package via the direct dependency `actionpack@4.2.5`
- The dependency with an issue was [rack@1.6.4](https://snyk.io/vuln/rubygems:rack@1.6.4)

Take the following `upgrade` path:
```
[
  false,
  "actionpack@5.0.0",
  "rack@2.0.1"
]
```
Assuming this was returned as a result of a test, then we know:
- The package that was tested is not upgradable (`false`)
- The direct dependency `actionpack` should be upgraded to at least version `5.0.0` in order to fix the issue
- Upgrading `actionpack` to version `5.0.0` will cause `rack` to be installed at version `2.0.1`

If the `upgrade` path comes back as an empty array (`[]`) then this means that there is no upgrade path available which would fix the issue.

### License Issue
A license issue has no additional fields other than the ones in "Issue".

### Snyk Organisation
The organisation in Snyk this request is applicable to. The organisation determines the access rights, licenses policy and is the unit of billing for private projects.

A Snyk organisation has these fields:

Property    | Type   | Description                   | Example                                |
-----------:| ------ | ----------------------------- | -------------------------------------- |
name        | string | The organisation display name | "deelmaker"                            |
id          | string | The ID of the organisation    | "3ab0f8d3-b17d-4953-ab6d-e1cbfe1df385" |

## Errors
This is a beta release of this API. Therefore, despite out efforts, errors might occur. In the unlikely event of such an error, it will have the following structure as JSON in the body:

Property    | Type   | Description                   | Example                                |
-----------:| ------ | ----------------------------- | -------------------------------------- |
message     | string | Error message with reference  | Error calling Snyk api (reference: 39db46b1-ad57-47e6-a87d-e34f6968030b) |
errorRef    | V4 uuid | An error ref to contact Snyk with | 39db46b1-ad57-47e6-a87d-e34f6968030b |

The error reference will also be supplied in the `x-error-reference` header in the server reply.

Example response:
```http
HTTP/1.1 500 Internal Server Error
x-error-reference: a45ec9c1-065b-4f7b-baf8-dbd1552ffc9f
Content-Type: application/json; charset=utf-8
Content-Length: 1848
Vary: Accept-Encoding
Date: Sun, 10 Sep 2017 06:48:40 GMT
```
# Group General

## The API Details [/]

### General API Documentation [GET]
General API Documentation can be found by sending a GET request to `https://snyk.io/api/v1/`.
+ Response 200 (application/json; charset=utf-8)

        {
            "what orgs can the current token access?": "https://snyk.io/api/v1/orgs",
            "what projects are owned by this org?": "https://snyk.io/api/v1/org/:id/projects",
            "test a package for issues": "https://snyk.io/api/v1/test/:packageManager/:packageName/:packageVersion"
        }
# Group Users

## User Notification settings [/user/me/notification-settings]
The user notification settings that will determine which emails are sent.

### Get notification settings [GET]
+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification Settings Response)

### Modify notification settings [PUT]
+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY
    + Attributes (Notification Settings Request)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification Settings Response)

## User Organisation Notification settings [/user/me/notification-settings/org/{orgId}]
The organisation notification settings for the user that will determine which emails are sent.

### Get org notification settings [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must have access to this organisation.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification Settings Response)


### Modify org notification settings [PUT]
+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY
    + Attributes (Notification Settings Request)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification Settings Response)

## User Project Notification settings [/user/me/notification-settings/org/{orgId}/project/{projectId}]
The project notification settings for the user that will determine which emails are sent.

### Get project notification settings [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must have access to this organisation.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to return notification settings for.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification Settings Response)

### Modify project notification settings [PUT]
+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY
    + Attributes (Notification Settings Request)

+ Response 200 (application/json; charset=utf-8)
# Group Groups
A group is a set of multiple organisations.

## Organisations in groups [/group/{id}/org]
+ Parameters
    + id: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The group ID. The `API_KEY` must have access to this group.


### Create a new Organisation in the group [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Create organisations body)

+ Response 200 (application/json; charset=utf-8)

# Data Structures

## Create organisations body
  + name (string) - The name of the new organisation
  + sourceOrgId (string, optional) - The id of an organisation to copy settings from (optional).

  This organisation must be associated with the same group.

  The items that will be copied are:
    \+ Source control integrations (GitHub, Gitlab, Bitbucker...).
    \+ Platform as a Service and Serverless integrations (Heroku, AWS Lamda...).
    \+ Notification integrations (Slack, Jira...)
    \+ Licence policy
    \+ Ignore policy
    \+ Language settings

## List members in a group [/group/{groupId}/members]
+ Parameters
    + groupId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The group ID. The `API_KEY` must have access admin to this group.

### List all members in a group [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

    + Attributes (array)
        + (object)
            + id (string) - The id of the user.
            + name (string) - The name of the user.
            + username (string) - The username of the user.
            + email (string) - The email of the user.
            + orgs (array)
                + (object)
                    + name (string) - The name of the organisation
                    + role (string) - the role of the user in the organisation
            + groupRole (string) - (Optional) The role of the user in the group.

## Members in an organisation of a group [/group/{groupId}/org/{orgId}/members]
+ Parameters
    + groupId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The group ID. The `API_KEY` must have access admin to this group.
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID we want to add the member to. The `API_KEY` must have access to this organisation.

### Add a member to an organisation from another organisation in the group [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Add member body)

+ Response 200 (application/json; charset=utf-8)

# Data Structures

## Add member body
  + userId (string) - The id of the user.
  + role (string) - The role of the user, "admin" or "collaborator".
# Group Organisations

## The Snyk Organisation For A Request [/orgs]
Each request to Snyk has to be done in the context of a Snyk organisation. If no org is specified, the user's default organisation (user is identified according to the `API_KEY`) will be used.
The organisation determines the access rights, licenses policy and is the unit of billing for private projects.

An organisation should be given as a query parameter named `org`, with the public identifier given to this org. The list of organisations and their corresponding public ids can be found with the org resource.


### List All The Organisations A User Belongs To [GET]
+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

        {
            "orgs": [
                {
                    "name":"defaultOrg",
                    "id":"689ce7f9-7943-4a71-b704-2ba575f01089",
                    "group": null
                },
                {
                    "name":"My Other Org",
                    "id":"a04d9cbd-ae6e-44af-b573-0556b0ad4bd2",
                    "group": {
                        "name": "ACME Inc.",
                        "id": "a060a49f-636e-480f-9e14-38e773b2a97f"
                    }
                }
            ]
        }

## Notification settings [/org/{orgId}/notification-settings]
Manage the default settings for org notifications. These will be used as defaults, but can be re-defined by org members.

### Get org notification settings [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must have access to this organisation.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification Settings Response)

### Set notification settings [PUT]
+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY
    + Attributes (Notification Settings Request)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification Settings Response)

## User invitation to organisation [/org/{orgId}/invite]
Invite users to the organisation by email.

### Invite users [POST]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must have admin access to this organisation.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + email (string) - The email of the user.
        + isAdmin (string, optional) - (optional) Set the role as admin.

+ Response 200 (application/json; charset=utf-8)

## Members in organisation [/org/{orgId}/members]
Manage members in your organisation.

### List Members [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must have admin access to this organisation.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

    + Attributes (array)
        + (object)
            + id (string) - The id of the user.
            + name (string) - The name of the user.
            + username (string) - The username of the user.
            + email (string) - The email of the user.
            + role (string) - The role of the user in the organisation.

## Manage roles in organisation [/org/{orgId}/members/{userId}]
Manage member's roles in your organisation.

### Update a member in the organisation [PUT]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must have admin access to this organisation.
    + userId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The user ID.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + role (string) - The new role of the user, "admin" or "collaborator".

+ Response 200 (application/json; charset=utf-8)

### Remove a member from the organisation [DELETE]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must admin have access to this organisation.
    + userId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The user ID we want to remove.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
# Group Integrations
Integrations are connections to places where code lives. They can be configured from the [integration settings](https://app.snyk.io/manage/integrations) page.

## Import projects [/org/{orgId}/integrations/{integrationId}/import]

### Import [POST]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must admin have access to this organisation.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The ID of the integration. Can be found on the [integration settings](https://app.snyk.io/manage/integrations) page.

+ Request GitHub, GH Enterprise, Bitbucket Cloud and Azure Repos (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + owner (string) - owner of the repo
            + name (string) - name of the repo
            + branch (string) - the branch we need
        + files (array, optional) - (Optional) an array of files to get
            + (object)
                + path (string) - path to the file

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request GitLab (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + id (number) - id of the repo
            + branch (string) - the branch we need
        + files (array, optional) - (Optional) an array of files to get
            + (object)
                + path (string) - path to the file

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request BitBucket Server (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + projectKey (string) - owner of the repo
            + name (string) - name of the repo
            + repoSlug (string) - the branch we need
        + files (array, optional) - (Optional) an array of files to get
            + (object)
                + path (string) - path to the file

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request Heroku (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + appId (string) - ID of the app
            + slugId (string) - ID of the slug
        + files (array, optional) - (Optional) an array of files to get
            + (object)
                + path (string) - path to the file

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request AWS Lambda (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + functionId (string) - ID of the app
        + files (array, optional) - (Optional) an array of files to get
            + (object)
                + path (string) - path to the file

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request CloudFoundry, Pivotal & IBM Cloud (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + appId (string) - ID of the app
        + files (array, optional) - (Optional) an array of files to get
            + (object)
                + path (string) - path to the file

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

## Get import job details [/org/{orgId}/integrations/{integrationId}/import/{jobId}]

### Import [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must admin have access to this organisation.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The ID of the integration. Can be found on the [integration settings](https://app.snyk.io/manage/integrations) page.
    + jobId: `1a325d9d-b782-468a-a242-9a2073734f0b` (string, required) - The ID of the job.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

        {
          "id": "dce061f7-ce0f-4ccf-b49b-4335d1205bd9",
          "status": "pending",
          "created": "2018-07-23T15:21:10.611Z",
          "logs": [
            {
              "name": "org1/repo1",
              "created": "2018-07-23T15:21:10.643Z",
              "status": "failed",
              "projects": []
            },
            {
              "name": "org2/repo2",
              "created": "2018-07-23T15:21:10.644Z",
              "status": "complete",
              "projects": [
                {
                  "targetFile": "package.json",
                  "success": true,
                  "projectUrl": "https://snyk.io/org/org-name/project/7eeaee25-5f9b-4d05-8818-4cca2c9d9adc"
                }
              ]
            },
            {
              "name": "org3/repo3",
              "created": "2018-07-23T15:21:10.643Z",
              "status": "pending",
              "projects": [
                {
                  "targetFile": "package.json",
                  "success": true,
                  "projectUrl": "https://snyk.io/org/org-name/project/0382897c-0617-4429-86df-51187dfd42f6"
                }
              ]
            }
          ]
        }

## Integration settings [/org/{orgId}/integrations/{integrationId}/settings]

### Settings [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must admin have access to this organisation.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The ID of the integration. Can be found on the [integration settings](https://app.snyk.io/manage/integrations) page.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

        {
          pullRequestTestEnabled: true,
          pullRequestFailOnAnyVulns: true,
          pullRequestFailOnlyForHighSeverity: true,
        }

### Settings [PUT]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must admin have access to this organisation.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The ID of the integration. Can be found on the [integration settings](https://app.snyk.io/manage/integrations) page.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "pullRequestTestEnabled": true,
                "pullRequestFailOnAnyVulns": false,
                "pullRequestFailOnlyForHighSeverity": true
            }

+ Response 200 (application/json; charset=utf-8)

        {
          pullRequestTestEnabled: true,
          pullRequestFailOnAnyVulns: false,
          pullRequestFailOnlyForHighSeverity: true,
        }

### Settings [DELETE]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must admin have access to this organisation.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The ID of the integration. Can be found on the [integration settings](https://app.snyk.io/manage/integrations) page.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 204 (application/json; charset=utf-8)
# Group Projects
A project is a package that is actively tracked by Snyk.

## All Projects [/org/{id}/projects]
+ Parameters
    + id: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID to list projects for. The `API_KEY` must have access to this organisation.

### List All Projects [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (List All Projects)

    + Body

            {
                "org": {
                    "name": "defaultOrg",
                    "id": "689ce7f9-7943-4a71-b704-2ba575f01089"
                    },
                "projects": [
                    {
                        "name": "atokeneduser/goof",
                        "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
                        "created": "2018-10-29T09:50:54.014Z",
                        "origin": "cli",
                        "type": "npm",
                        "readOnly": "false",
                        "testFrequency": "daily",
                        "totalDependencies": 438,
                        "issueCountsBySeverity": {
                            "low": 8,
                            "high": 13,
                            "medium": 15,
                        },
                        "lastTestedDate": "2019-02-05T06:21:00.000Z"
                    },
                    {
                        "name": "atokeneduser/clojure",
                        "id": "af127b96-6966-46c1-826b-2e79ac49bbd9",
                        "created": "2018-10-29T09:50:54.014Z",
                        "origin": "github",
                        "type": "maven",
                        "readOnly": "false",
                        "testFrequency": "hourly",
                        "totalDependencies": 42,
                        "issueCountsBySeverity": {
                            "low": 8,
                            "high": 13,
                            "medium": 21,
                        },
                        "lastTestedDate": "2019-02-05T07:01:00.000Z"
                    },
                    {
                        "name": "docker-image|alpine",
                        "id": "f6c8339d-57e1-4d64-90c1-81af0e811f7e",
                        "created": "2019-02-04T08:54:07.704Z",
                        "origin": "cli",
                        "type": "apk",
                        "readOnly": "false",
                        "testFrequency": "daily",
                        "totalDependencies": 14,
                        "issueCountsBySeverity": {
                            "low": 0,
                            "high": 0,
                            "medium": 0
                        },
                        "imageId": "sha256:caf27325b298a6730837023a8a342699c8b7b388b8d878966b064a1320043019",
                        "imageTag": "latest",
                        "lastTestedDate": "2019-02-05T08:54:07.704Z"
                    }
                ]
            }

## Individual Project [/org/{orgId}/project/{projectId}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID the project belongs to. The `API_KEY` must have access to this organisation.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID.

### Delete a Project [DELETE]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

## Project Issues [/org/{orgId}/project/{projectId}/issues]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must have access to this organisation.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to return issues for.

### List All Issues [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Project Issues Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Project Issues)

    + Body

            {
                "ok": false,
                "issues": {
                    "vulnerabilities": [
                        {
                            "id": "npm:ms:20170412",
                            "url": "https://snyk.io/vuln/npm:ms:20170412",
                            "title": "Regular Expression Denial of Service (ReDoS)",
                            "type": "vuln",
                            "description": "## Overview\n[`ms`](https://www.npmjs.com/package/ms) is a tiny millisecond conversion utility.\n\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) due to an incomplete fix for previously reported vulnerability [npm:ms:20151024](https://snyk.io/vuln/npm:ms:20151024). The fix limited the length of accepted input string to 10,000 characters, and turned to be insufficient making it possible to block the event loop for 0.3 seconds (on a typical laptop) with a specially crafted string passed to `ms()` function.\n\n*Proof of concept*\n```js\nms = require('ms');\nms('1'.repeat(9998) + 'Q') // Takes about ~0.3s\n```\n\n**Note:** Snyk's patch for this vulnerability limits input length to 100 characters. This new limit was deemed to be a breaking change by the author.\nBased on user feedback, we believe the risk of breakage is _very_ low, while the value to your security is much greater, and therefore opted to still capture this change in a patch for earlier versions as well.  Whenever patching security issues, we always suggest to run tests on your code to validate that nothing has been broken.\n\nFor more information on `Regular Expression Denial of Service (ReDoS)` attacks, go to our [blog](https://snyk.io/blog/redos-and-catastrophic-backtracking/).\n\n## Disclosure Timeline\n- Feb 9th, 2017 - Reported the issue to package owner.\n- Feb 11th, 2017 - Issue acknowledged by package owner.\n- April 12th, 2017 - Fix PR opened by Snyk Security Team.\n- May 15th, 2017 - Vulnerability published.\n- May 16th, 2017 - Issue fixed and version `2.0.0` released.\n- May 21th, 2017 - Patches released for versions `>=0.7.1, <=1.0.0`.\n\n## Remediation\nUpgrade `ms` to version 2.0.0 or higher.\n\n## References\n- [GitHub PR](https://github.com/zeit/ms/pull/89)\n- [GitHub Commit](https://github.com/zeit/ms/pull/89/commits/305f2ddcd4eff7cc7c518aca6bb2b2d2daad8fef)\n",
                            "from": [
                                "mongoose@4.2.4",
                                "mquery@1.6.3",
                                "debug@2.2.0",
                                "ms@0.7.1"
                            ],
                            "package": "ms",
                            "version": "0.7.1",
                            "severity": "low",
                            "language": "js",
                            "packageManager": "npm",
                            "semver": {
                                "unaffected": ">=2.0.0",
                                "vulnerable": "<2.0.0"
                            },
                            "publicationTime": "2017-05-15T06:02:45.497Z",
                            "disclosureTime": "2017-04-11T21:00:00.000Z",
                            "isUpgradable": true,
                            "isPatchable": true,
                            "identifiers": {
                                "CVE": [],
                                "CWE": [
                                    "CWE-400"
                                ],
                                "ALTERNATIVE": [
                                    "SNYK-JS-MS-10509"
                                ]
                            },
                            "credit": [
                                "Snyk Security Research Team"
                            ],
                            "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                            "cvssScore": 3.7,
                            "patches": [
                                {
                                    "id": "patch:npm:ms:20170412:0",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/ms/20170412/ms_100.patch"
                                    ],
                                    "version": "=1.0.0",
                                    "comments": [],
                                    "modificationTime": "2017-05-16T10:12:18.990Z"
                                },
                                {
                                    "id": "patch:npm:ms:20170412:1",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/ms/20170412/ms_072-073.patch"
                                    ],
                                    "version": "=0.7.2 || =0.7.3",
                                    "comments": [],
                                    "modificationTime": "2017-05-16T10:12:18.990Z"
                                },
                                {
                                    "id": "patch:npm:ms:20170412:2",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/ms/20170412/ms_071.patch"
                                    ],
                                    "version": "=0.7.1",
                                    "comments": [],
                                    "modificationTime": "2017-05-16T10:12:18.990Z"
                                }
                            ],
                            "isIgnored": true,
                            "isPatched": false,
                            "upgradePath": [
                                "mongoose@4.10.2",
                                "mquery@2.3.1",
                                "debug@2.6.8",
                                "ms@2.0.0"
                            ]
                        },
                        {
                            "id": "npm:qs:20170213",
                            "url": "https://snyk.io/vuln/npm:qs:20170213",
                            "title": "Prototype Override Protection Bypass",
                            "type": "vuln",
                            "description": "## Overview\n[`qs`](https://www.npmjs.com/package/qs) is a querystring parser that supports nesting and arrays, with a depth limit.\n\nBy default `qs` protects against attacks that attempt to overwrite an object's existing prototype properties, such as `toString()`, `hasOwnProperty()`,etc.\n\nFrom [`qs` documentation](https://github.com/ljharb/qs):\n> By default parameters that would overwrite properties on the object prototype are ignored, if you wish to keep the data from those fields either use plainObjects as mentioned above, or set allowPrototypes to true which will allow user input to overwrite those properties. WARNING It is generally a bad idea to enable this option as it can cause problems when attempting to use the properties that have been overwritten. Always be careful with this option.\n\nOverwriting these properties can impact application logic, potentially allowing attackers to work around security controls, modify data, make the application unstable and more.\n\nIn versions of the package affected by this vulnerability, it is possible to circumvent this protection and overwrite prototype properties and functions by prefixing the name of the parameter with `[` or `]`. e.g. `qs.parse(\"]=toString\")` will return `{toString = true}`, as a result, calling `toString()` on the object will throw an exception.\n\n**Example:**\n```js\nqs.parse('toString=foo', { allowPrototypes: false })\n// {}\n\nqs.parse(\"]=toString\", { allowPrototypes: false })\n// {toString = true} <== prototype overwritten\n```\n\nFor more information, you can check out our [blog](https://snyk.io/blog/high-severity-vulnerability-qs/).\n\n## Disclosure Timeline\n- February 13th, 2017 - Reported the issue to package owner.\n- February 13th, 2017 - Issue acknowledged by package owner.\n- February 16th, 2017 - Partial fix released in versions `6.0.3`, `6.1.1`, `6.2.2`, `6.3.1`.\n- March 6th, 2017     - Final fix released in versions `6.4.0`,`6.3.2`, `6.2.3`, `6.1.2` and `6.0.4`\n\n## Remediation\nUpgrade `qs` to version `6.4.0` or higher.\n**Note:** The fix was backported to the following versions `6.3.2`, `6.2.3`, `6.1.2`, `6.0.4`.\n\n## References\n- [GitHub Commit](https://github.com/ljharb/qs/commit/beade029171b8cef9cee0d03ebe577e2dd84976d)\n- [Report of an insufficient fix](https://github.com/ljharb/qs/issues/200)\n",
                            "from": [
                                "qs@0.0.6"
                            ],
                            "package": "qs",
                            "version": "0.0.6",
                            "severity": "high",
                            "language": "js",
                            "packageManager": "npm",
                            "semver": {
                                "unaffected": ">=6.4.0 || ~6.3.2 || ~6.2.3 || ~6.1.2 || ~6.0.4",
                                "vulnerable": "<6.3.2 >=6.3.0 || <6.2.3 >=6.2.0 || <6.1.2 >=6.1.0 || <6.0.4"
                            },
                            "publicationTime": "2017-03-01T10:00:54.163Z",
                            "disclosureTime": "2017-02-13T00:00:00.000Z",
                            "isUpgradable": true,
                            "isPatchable": false,
                            "identifiers": {
                                "CVE": [],
                                "CWE": [
                                    "CWE-20"
                                ],
                                "ALTERNATIVE": [
                                    "SNYK-JS-QS-10407"
                                ]
                            },
                            "credit": [
                                "Snyk Security Research Team"
                            ],
                            "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            "cvssScore": 7.4,
                            "patches": [
                                {
                                    "id": "patch:npm:qs:20170213:0",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/qs/20170213/630_632.patch"
                                    ],
                                    "version": "=6.3.0",
                                    "comments": [],
                                    "modificationTime": "2017-03-09T00:00:00.000Z"
                                },
                                {
                                    "id": "patch:npm:qs:20170213:1",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/qs/20170213/631_632.patch"
                                    ],
                                    "version": "=6.3.1",
                                    "comments": [],
                                    "modificationTime": "2017-03-09T00:00:00.000Z"
                                },
                                {
                                    "id": "patch:npm:qs:20170213:2",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/qs/20170213/621_623.patch"
                                    ],
                                    "version": "=6.2.1",
                                    "comments": [],
                                    "modificationTime": "2017-03-09T00:00:00.000Z"
                                },
                                {
                                    "id": "patch:npm:qs:20170213:3",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/qs/20170213/622_623.patch"
                                    ],
                                    "version": "=6.2.2",
                                    "comments": [],
                                    "modificationTime": "2017-03-09T00:00:00.000Z"
                                },
                                {
                                    "id": "patch:npm:qs:20170213:4",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/qs/20170213/610_612.patch"
                                    ],
                                    "version": "=6.1.0",
                                    "comments": [],
                                    "modificationTime": "2017-03-09T00:00:00.000Z"
                                },
                                {
                                    "id": "patch:npm:qs:20170213:5",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/qs/20170213/611_612.patch"
                                    ],
                                    "version": "=6.1.1",
                                    "comments": [],
                                    "modificationTime": "2017-03-09T00:00:00.000Z"
                                },
                                {
                                    "id": "patch:npm:qs:20170213:6",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/qs/20170213/602_604.patch"
                                    ],
                                    "version": "=6.0.2",
                                    "comments": [],
                                    "modificationTime": "2017-03-09T00:00:00.000Z"
                                },
                                {
                                    "id": "patch:npm:qs:20170213:7",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/qs/20170213/603_604.patch"
                                    ],
                                    "version": "=6.0.3",
                                    "comments": [],
                                    "modificationTime": "2017-03-09T00:00:00.000Z"
                                }
                            ],
                            "isIgnored": true,
                            "isPatched": false,
                            "upgradePath": [
                                "qs@6.0.4"
                            ],
                            "ignored": [
                                {
                                    "reason": "Test reason",
                                    "expires": "2100-01-01T00:00:00.000Z",
                                    "source": "cli"
                                }
                            ]
                        },
                        {
                            "id": "npm:mongoose:20160116",
                            "url": "https://snyk.io/vuln/npm:mongoose:20160116",
                            "title": "Remote Memory Exposure",
                            "type": "vuln",
                            "description": "## Overview\nA potential memory disclosure vulnerability exists in mongoose.\nA `Buffer` field in a MongoDB document can be used to expose sensitive\ninformation such as code, runtime memory and user data into MongoDB.\n\n### Details\nInitializing a `Buffer` field in a document with integer `N` creates a `Buffer`\nof length `N` with non zero-ed out memory.\n**Example:**\n```\nvar x = new Buffer(100); // uninitialized Buffer of length 100\n// vs\nvar x = new Buffer('100'); // initialized Buffer with value of '100'\n```\nInitializing a MongoDB document field in such manner will dump uninitialized\nmemory into MongoDB.\nThe patch wraps `Buffer` field initialization in mongoose by converting a\n`number` value `N` to array `[N]`, initializing the `Buffer` with `N` in its\nbinary form.\n\n#### Proof of concept\n```javascript\nvar mongoose = require('mongoose');\nmongoose.connect('mongodb://localhost/bufftest');\n\n// data: Buffer is not uncommon, taken straight from the docs: http://mongoosejs.com/docs/schematypes.html\nmongoose.model('Item', new mongoose.Schema({id: String, data: Buffer}));\n\nvar Item = mongoose.model('Item');\n\nvar sample = new Item();\nsample.id = 'item1';\n\n// This will create an uninitialized buffer of size 100\nsample.data = 100;\nsample.save(function () {\n    Item.findOne(function (err, result) {\n        // Print out the data (exposed memory)\n        console.log(result.data.toString('ascii'))\n        mongoose.connection.db.dropDatabase(); // Clean up everything\n        process.exit();\n    });\n});\n```\n\n## Remediation\nUpgrade `mongoose` to version >= 3.8.39 or >= 4.3.6.\n\nIf a direct dependency update is not possible, use [`snyk wizard`](https://snyk.io/docs/using-snyk#wizard) to patch this vulnerability.\n\n## References\n- [GitHub Issue](https://github.com/Automattic/mongoose/issues/3764)\n- [Blog: Node Buffer API fix](https://github.com/ChALkeR/notes/blob/master/Lets-fix-Buffer-API.md#previous-materials)\n- [Blog: Information about Buffer](https://github.com/ChALkeR/notes/blob/master/Buffer-knows-everything.md)\n",
                            "from": [
                                "mongoose@4.2.4"
                            ],
                            "package": "mongoose",
                            "version": "4.2.4",
                            "severity": "medium",
                            "language": "js",
                            "packageManager": "npm",
                            "semver": {
                                "unaffected": "<3.5.5 || >=4.3.6",
                                "vulnerable": "<3.8.39 >=3.5.5 || <4.3.6 >=4.0.0"
                            },
                            "publicationTime": "2016-01-23T12:00:05.158Z",
                            "disclosureTime": "2016-01-23T12:00:05.158Z",
                            "isUpgradable": true,
                            "isPatchable": true,
                            "identifiers": {
                                "CVE": [],
                                "CWE": [
                                    "CWE-201"
                                ],
                                "ALTERNATIVE": [
                                    "SNYK-JS-MONGOOSE-10081"
                                ]
                            },
                            "credit": [
                                "ChALkeR"
                            ],
                            "CVSSv3": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "cvssScore": 5.1,
                            "patches": [
                                {
                                    "id": "patch:npm:mongoose:20160116:0",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/mongoose/20160116/20160116_0_0_mongoose_8066b145c07984c8b7e56dbb51721c0a3d48e18a.patch"
                                    ],
                                    "version": "<4.3.6 >=4.1.2",
                                    "comments": [],
                                    "modificationTime": "2016-01-23T12:00:05.158Z"
                                },
                                {
                                    "id": "patch:npm:mongoose:20160116:1",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/mongoose/20160116/20160116_0_1_mongoose_8066b145c07984c8b7e56dbb51721c0a3d48e18a.patch"
                                    ],
                                    "version": "<4.1.2 >=4.0.0",
                                    "comments": [],
                                    "modificationTime": "2016-01-23T12:00:05.158Z"
                                },
                                {
                                    "id": "patch:npm:mongoose:20160116:2",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/mongoose/20160116/20160116_0_3_mongoose_2ff7d36c5e52270211b17f3a84c8a47c6f4d8c1f.patch"
                                    ],
                                    "version": "<3.8.39 >=3.6.11",
                                    "comments": [],
                                    "modificationTime": "2016-01-23T12:00:05.158Z"
                                },
                                {
                                    "id": "patch:npm:mongoose:20160116:3",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/mongoose/20160116/20160116_0_5_mongoose_2ff7d36c5e52270211b17f3a84c8a47c6f4d8c1f.patch"
                                    ],
                                    "version": "=3.6.11",
                                    "comments": [],
                                    "modificationTime": "2016-01-23T12:00:05.158Z"
                                },
                                {
                                    "id": "patch:npm:mongoose:20160116:4",
                                    "urls": [
                                        "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/develop/patches/npm/mongoose/20160116/20160116_0_4_mongoose_2ff7d36c5e52270211b17f3a84c8a47c6f4d8c1f.patch"
                                    ],
                                    "version": "<3.6.10 >=3.5.5",
                                    "comments": [],
                                    "modificationTime": "2016-01-23T12:00:05.158Z"
                                }
                            ],
                            "isIgnored": false,
                            "isPatched": true,
                            "upgradePath": [
                                "mongoose@4.3.6"
                            ],
                            "patched": [
                                {
                                    "patched": "2016-10-24T10:50:51.980Z"
                                }
                            ]
                        }
                    ],
                    "licenses": []
                },
                "dependencyCount": 250,
                "packageManager": "npm"
            }

## Project Dependency Graph [/org/{orgId}/project/{projectId}/dep-graph]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID. The `API_KEY` must have access to this organisation.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to return issues for.
### Get Project Dependency Graph [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    * A reference implementation of the graph, as well as conversion functions to/from legacy tree format, can be found at: https://github.com/snyk/dep-graph.
    * The object might contain additional fields in the future, in a backward-compatible way (`schemaVersion` will change accordingly).

    + Attributes (Project Dependency Graph)

    + Body

            {
                "depGraph": {
                    "schemaVersion": "1.1.0",
                    "pkgManager": {
                        "name": "npm"
                    },
                    "pkgs": [
                        {
                            "id": "demo-app-for-test@1.1.1",
                            "info": {
                                "name": "demo-app-for-test",
                                "version": "1.1.1"
                            }
                        },
                        {
                            "id": "express@4.4.0",
                            "info": {
                                "name": "express",
                                "version": "4.4.0"
                            }
                        },
                        {
                            "id": "ws@1.0.0",
                            "info": {
                                "name": "ws",
                                "version": "1.0.0"
                            }
                        }
                    ],
                    "graph": {
                        "rootNodeId": "root-node",
                        "nodes": [
                            {
                                "nodeId": "root-node",
                                "pkgId": "demo-app-for-test@1.1.1",
                                "deps": [
                                    {
                                        "nodeId": "express@4.4.0"
                                    },
                                    {
                                        "nodeId": "ws@1.0.0"
                                    }
                                ]
                            },
                            {
                                "nodeId": "express@4.4.0",
                                "pkgId": "express@4.4.0",
                                "deps": []
                            },
                            {
                                "nodeId": "ws@1.0.0",
                                "pkgId": "ws@1.0.0",
                                "deps": []
                            }
                        ]
                    }
                }
            }
## Project Ignores [/org/{orgId}/project/{projectId}/ignores]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID to list ignores for. The `API_KEY` must have access to this organisation.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID to list ignores for.

### List All Ignores [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

    + Attributes (All Ignores)

    + Body

            {
                "npm:qs:20140806-1": [
                    {
                        "*": {
                            "reason": "No fix available",
                            "created": "2017-10-31T11:24:00.932Z",
                            "ignoredBy": {
                                "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                                "name": "Joe Bloggs",
                                "email": "jbloggs@gmail.com"
                            },
                            "reasonType": "tempoarary-ignore",
                            "disregardIfFixable": true
                        }
                    }
                ],
                "npm:negotiator:20160616": [
                    {
                        "*": {
                            "reason": "Not vulnerable via this path",
                            "created": "2017-10-31T11:24:45.365Z",
                            "ignoredBy": {
                                "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                                "name": "Joe Bloggs",
                                "email": "jbloggs@gmail.com"
                            },
                            "reasonType": "not-vulnerable",
                            "disregardIfFixable": false
                        }
                    }
                ],
                "npm:electron:20170426": [
                    {
                        "*": {
                            "reason": "Low impact",
                            "created": "2017-10-31T11:25:17.138Z",
                            "ignoredBy": {
                                "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                                "name": "Joe Bloggs",
                                "email": "jbloggs@gmail.com"
                            },
                            "reasonType": "wont-fix",
                            "disregardIfFixable": false
                        }
                    }
                ]
            }

## Project Ignores By Issue [/org/{orgId}/project/{projectId}/ignore/{issueId}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID to modify ignores for. The `API_KEY` must have access to this organisation.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID to modify ignores for.
    + issueId: `npm:qs:20140806-1` (string, required) - The issue ID to modify ignores for.

### Add Ignore [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Ignore Rule)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Ignore)

    + Body

            {
                "*": {
                    "reason": "No fix available",
                    "created": "2017-10-31T11:24:00.932Z",
                    "ignoredBy": {
                        "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                        "name": "Joe Bloggs",
                        "email": "jbloggs@gmail.com"
                    },
                    "reasonType": "tempoarary-ignore",
                    "disregardIfFixable": true
                }
            }

### Replace Ignores [PUT]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Ignore Rules)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Ignores)

    + Body

            [
                {
                    "*": {
                        "reason": "No fix available",
                        "created": "2017-10-31T11:24:00.932Z",
                        "ignoredBy": {
                            "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                            "name": "Joe Bloggs",
                            "email": "jbloggs@gmail.com"
                        },
                        "reasonType": "tempoarary-ignore",
                        "disregardIfFixable": true
                    }
                }
            ]

### Delete Ignores [DELETE]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

## Project Jira Issues - [/org/{orgId}/project/{projectId}/jira-issues]

If you have configured an integration with Jira, it is possible to create Jira issues for project vulnerabilities or license issues directly from the Snyk API.

The Jira integration is available to customers on the pro or enterprise plan.

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID to list Jira issues for. The `API_KEY` must have access to this organisation.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID to list Jira issues for.

### List All Jira Issues [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

    + Attributes (All Jira Issues)

    + Body

            {
                "npm:qs:20140806-1": [
                    {
                        "jiraIssue": {
                            "id": "10001",
                            "key": "EX-1",
                        }
                    }
                ],
                "npm:negotiator:20160616": [
                    {
                        "jiraIssue": {
                            "id": "10002",
                            "key": "EX-2",
                        }
                    }
                ]
            }

### Create Jira Issue [POST /org/{orgId}/project/{projectId}/issue/{issueId}/jira-issue]
+ Parameters
    + issueId: `npm:qs:20140806-1` (string, required) - The issue ID to create Jira issue for.

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Jira Issue Request)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Jira Issue)

    + Body

            {
                "jiraIssue": {
                    "id": "10001",
                    "key": "EX-1",
                }
            }


## Project Settings [/org/{orgId}/project/{projectId}/settings]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID to which the project belongs. The API_KEY must have access to this organisation.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID

### List Project Settings [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
The response will contain only attributes that can be updated (see `ATTRIBUTES` section in `Update Project Settings`) and that have been previously set.

    + Body

            {
                "pullRequestTestEnabled": true,
            }

### Update Project Settings [PUT]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Project Settings)

    + Body

            {
                "pullRequestTestEnabled": true,
                "pullRequestFailOnAnyVulns": false,
                "pullRequestFailOnlyForHighSeverity": true
            }

+ Response 200 (application/json; charset=utf-8)
The response will contain the attributes and values that have been sent in the request and successfully updated.

    + Body

                {
                    "pullRequestTestEnabled": true,
                    "pullRequestFailOnAnyVulns": false,
                    "pullRequestFailOnlyForHighSeverity": true
                }


# Data Structures

## List All Projects (object)
+ org (object)
    + name (string)
    + id (string) - The identifier of the org
+ projects (array, fixed-type) - A list of org's projects
    + (object)
        + name (string)
        + id (string) - The project identifier
        + created (string) - The date that the project was created on
        + origin (string) - The origin the project was added from
        + type (string) - The package manager of the project
        + readOnly (boolean) - Whether the project is read-only
        + testFrequency (string) - The frequency of Snyk testing as defined in settings
        + totalDependencies (number) - Number of dependencies of the project
        + issueCountsBySeverity (object) - Number of known vulnerabilities in the project
            + low (number) - Number of low severity vulnerabilities
            + medium (number) - Number of medium severity vulnerabilities
            + high (number) - Number of high severity vulnerabilities
        + imageId (string) - For docker projects shows the ID of the image
        + imageTag (string) - For docker projects shows the tag of the image
        + lastTestedDate (string) -The date on which the most recent test was conducted for this project

## Project Issues (object)
+ ok (boolean, required) - Whether the project has issues (which are not ignored or patched)
+ issues (object, required)
    + vulnerabilities (array, fixed-type, required) - A list of vulnerability issues
        + (object, required)
            + id (string, required) - The identifier of the issue
            + url (string, required) - URL to a page containing information about the issue
            + title (string, required) - The issue title
            + description (string, required) - The issue description
            + from (array, required) - The path that the issue was introduced by
            + upgradePath (array, required) - The path to upgrade the package to a non-vulnerable version
            + package (string, required) - The name of the package that the issue relates to
            + version (string, required) - The version of the package that the issue relates to
            + severity (string, required) - The severity status of the issue
            + isUpgradable (boolean) - Whether the issue can be fixed by upgrading to a later version of the dependency
            + isPatchable (boolean) - Whether the issue can be patched
            + publicationTime (string) - The date that the vulnerability was first published by Snyk
            + disclosureTime (string) - The date that the vulnerability was first disclosed
            + language (string) - The language of the issue
            + packageManager (string) - The package manager of the issue
            + identifiers (object) - External identifiers assigned to the issue
                + CVE (array[string]) - Common Vulnerability Enumeration identifiers
                + CWE (array[string]) - Common Weakness Enumeration identifiers
                + OSVDB (array[string]) - Identifiers assigned by the Open Source Vulnerability Database (OSVDB)
            + credit (array[string]) - The list of people responsible for first uncovering or reporting the issue
            + CVSSv3 (string) - The CVSS v3 string that signifies how the CVSS score was calcualted
            + cvssScore (number) - The CVSS score that results from running the CVSSv3 string
            + patches (array) - A list of patches available for the given issue
                + (object)
                    + id (string) - The identifier of the patch
                    + urls (array[string]) - The URLs where the patch files can be downloaded
                    + version (string) - The version number(s) that the patch can be applied to
                    + comments (array[string]) - Any comments about the patch
                    + modificationTime (string) - When the patch was last modified
            + isIgnored (boolean, required) - Whether the issue has been ignored
            + isPatched (boolean, required) - Whether the issue has been patched
            + semver (object) - The ranges that are vulnerable and unaffected by the issue
                + vulnerable (string) - The ranges that are vulnerable to the issue
                + unaffected (string) - The ranges that are unaffected by the issue
            + ignored (array) - The list of reasons why the issue was ignored
                + (object)
                    + reason (string) - A reason why the issue was ignored
                    + expires (string) - The date when the ignore will no longer apply
                    + source (enum[string]) - The place where the ignore rule was applied from
                        + Members
                            + `cli` - The ignore was applied via the CLI or filesystem
                            + `api` - The ignore was applied via the API or website
            + patched (array) - The list of patches applied to the issue
                + (object)
                    + patched (string) - The date when the patch was applied
    + licenses (array, fixed-type, required) - A list of vulnerability issues
        + (object, required)
            + id (string, required) - The identifier of the issue
            + url (string, required) - URL to a page containing information about the issue
            + title (string, required) - The issue title
            + from (array, required) - The path that the issue was introduced by
            + package (string, required) - The name of the package that the issue relates to
            + version (string, required) - The version of the package that the issue relates to
            + severity (string, required) - The severity status of the issue
            + language (string) - The language of the issue
            + packageManager (string) - The package manager of the issue
            + isIgnored (boolean, required) - Whether the issue has been ignored
            + isPatched (boolean, required) - Whether the issue has been patched
            + ignored (array) - The list of reasons why the issue was ignored
                + (object)
                    + reason (string) - A reason why the issue was ignored
                    + expires (string) - The date when the ignore will no longer apply
                    + source (enum[string]) - The place where the ignore rule was applied from
                        + Members
                            + `cli` - The ignore was applied via the CLI or filesystem
                            + `api` - The ignore was applied via the API or website
            + patched (array) - The list of patches applied to the issue
                + (object)
                    + patched (string) - The date when the patch was applied
+ dependencyCount (number) - The number of dependencies the package has
+ packageManager (string) - The package manager of the project

## Project Dependency Graph (object)
+ depGraph (object, required) - The dependency-graph object
    + schemaVersion (string, required) - The scheme version of the depGraph object
    + pkgManager (object, required) - The package manager of the project
        + name (string, required) - The name of the package manager
        + version (string) - The version of the package manager
        + repositories (array, fixed-type)
            + alias: (string, required)
    + pkgs (array, fixed-type, required) - A list of dependencies in the project
        + (object, required)
            + id (string, required) - The internal id of the package
            + info (object, required)
                + name (string, required) - The name of the package
                + version (string) - The version of the package
    + graph (object, required) - A directional graph of the packages in the project
        + rootNodeId (string, required) - The internal id of the root node
        + nodes (array, fixed-type) - A list of the first-level packages
            + (object, required)
                + nodeId (string, required) - The internal id of the node
                + pkgId (string, required) - The id of the package
                + deps (array, fixed-type, required) - A list of the direct dependencies of the package
                    + (object, required)
                        + nodeId (string, required) - The id of the node

## Project Issues Filters
+ filters (object)
    + severities (array) - The severity levels of issues to filter the results by
        + high (string) - Include issues which are high severity
        + medium (string) - Include issues which are medium severity
        + low (string) - Include issues which are low severity
    + types (array) - The type of issues to filter the results by
        + vuln (string) - Include issues which are vulnerabilities
        + license (string) - Include issues which are licenses
    + ignored (boolean) - If set to `true`, only include issues which are ignored, if set to `false`, only include issues which are not ignored
    + patched (boolean) - If set to `true`, only include issues which are patched, if set to `false`, only include issues which are not patched

## All Ignores (object)
+ *issueId (string)* (array[Ignore], required) - The issue ID that should be ignored.

## Ignore (object)
+ *ignorePath (string)* (object, required) - The path that should be ignored. Wildcards can be specified with a `*`.
    + reason (string) - The reason that the issue was ignored.
    + reasonType (enum[string]) - The classification of the ignore.
        + Members
            + `not-vulnerable` - The app is not vulnerable.
            + `wont-fix` - The app may be vulnerable, but you accept the risk.
            + `temporary-ignore` - You don't want to fix the issue at the moment for any reason.
    + ignoredBy (object) - The person who ignored the issue.
        + name (string, required) - The name of the person who ignored the issue.
        + email (string, required) - The email of the person who ignored the issue.
        + id (string) - The user ID of the person who ignored the issue.
    + disregardIfFixable (boolean) - Only ignore the issue if no upgrade or patch is available.
    + expires (string) - The timestamp that the issue will no longer be ignored.
    + created (string) - The timestamp that the issue was ignored.

## Ignores (array)
+ (object)
    + *ignorePath (string)* (object, required) - The path that should be ignored. Wildcards can be specified with a `*`.
        + reason (string) - The reason that the issue was ignored.
        + reasonType (enum[string]) - The classification of the ignore.
            + Members
                + `not-vulnerable` - The app is not vulnerable.
                + `wont-fix` - The app may be vulnerable, but you accept the risk.
                + `temporary-ignore` - You don't want to fix the issue at the moment for any reason.
        + ignoredBy (object) - The person who ignored the issue.
            + name (string, required) - The name of the person who ignored the issue.
            + email (string, required) - The email of the person who ignored the issue.
            + id (string) - The user ID of the person who ignored the issue.
        + disregardIfFixable (boolean) - Only ignore the issue if no upgrade or patch is available.
        + expires (string) - The timestamp that the issue will no longer be ignored.
        + created (string) - The timestamp that the issue was ignored.

## Ignore Rule (object)
+ ignorePath (string) - The path to ignore (default is `*` which represents all paths).
+ disregardIfFixable (boolean) - Only ignore the issue if no upgrade or patch is available.
+ reason (string) - The reason that the issue was ignored.
+ reasonType (enum[string]) - The classification of the ignore.
    + Members
        + `not-vulnerable` - The app is not vulnerable.
        + `wont-fix` - The app may be vulnerable, but you accept the risk.
        + `temporary-ignore` - You don't want to fix the issue at the moment for any reason.
+ disregardIfFixable (boolean, required) - Only ignore the issue if no upgrade or patch is available.
+ expires (string) - The timestamp that the issue will no longer be ignored.

## Ignore Rules (array)
+ (object)
    + ignorePath (string) - The path to ignore (default is `*` which represents all paths).
    + disregardIfFixable (boolean) - Only ignore the issue if no upgrade or patch is available.
    + reason (string) - The reason that the issue was ignored.
    + reasonType (enum[string]) - The classification of the ignore.
        + Members
            + `not-vulnerable` - The app is not vulnerable.
            + `wont-fix` - The app may be vulnerable, but you accept the risk.
            + `temporary-ignore` - You don't want to fix the issue at the moment for any reason.
    + disregardIfFixable (boolean, required) - Only ignore the issue if no upgrade or patch is available.
    + expires (string) - The timestamp that the issue will no longer be ignored.

## All Jira Issues (object)
+ *issueId (string)* (array[Jira Issue], required) - The issue ID and relating Jira issue.

## Jira Issue (object)
+ jiraIssue (object) - The details about the Jira issue.
    + id (string) - The id of the issue in Jira.
    + key (string) - The key of the issue in Jira.

## Jira Issue Request (object)

+ fields (object) - See https://developer.atlassian.com/cloud/jira/platform/rest/#api-api-2-issue-post for details of what to send as fields.

## Project Settings (object)
+ pullRequestTestEnabled (boolean) - If set to `true`, Snyk Test checks PRs for vulnerabilities.
+ pullRequestFailOnAnyVulns (boolean) - If set to `true`, fail Snyk Test if the repo has any vulnerabilities. Otherwise, fail only when the PR is adding a vulnerable dependency.
+ pullRequestFailOnlyForHighSeverity (boolean) - If set to `true`, fail Snyk Test only for high severity vulnerabilities.
# Group Dependencies
Dependencies are packages/modules that your projects depend on.

## Dependencies By Organisation [/org/{orgId}/dependencies{?sortBy,order,page,perPage}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID to list projects for. The `API_KEY` must have access to this organisation.
    + sortBy: `dependency` (enum[string], optional) - The field to sort results by.
        + Default: `dependency`
        + Members
            + `projects`
            + `dependency`
            + `severity`
            + `dependenciesWithIssues`
    + order (enum[string], optional) - The direction to sort results by.
        + Default: `asc`
        + Members
            + `asc`
            + `desc`
    + page (number, optional) - The page of results to fetch.
        + Default: `1`
    + perPage (number, optional) - The number of results to fetch per page.
        + Default: `20`

### List All Dependencies [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Dependencies Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Dependencies)

    + Body

            {
                "results": [
                    {
                        "id": "gulp@3.9.1",
                        "name": "gulp",
                        "version": "3.9.1",
                        "latestVersion": "4.0.0",
                        "latestVersionPublishedDate": "2018-01-01T01:29:06.863Z",
                        "firstPublishedDate": "2013-07-04T23:27:07.828Z",
                        "isDeprecated": false,
                        "deprecatedVersions": ['0.0.1', '0.0.2', '0.0.3'],
                        "licenses": [
                            {
                                "id": "snyk:lic:npm:gulp:MIT",
                                "title": "MIT license",
                                "license": "MIT"
                            }
                        ],
                        "dependenciesWithIssues": [
                            "minimatch@2.0.10",
                            "minimatch@0.2.14"
                        ],
                        "packageManager": "npm",
                        "projects": [
                            {
                                "name": "atokeneduser/goof",
                                "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545"
                            }
                        ]
                    }
                ],
                "total": 1
            }

# Data Structures

## Dependencies (object)
+ results (array, fixed-type, required) - A list of issues
    + (object, required)
        + id (string, required) - The identifier of the package
        + name (string, required) - The name of the package
        + version (string, required) - The version of the package
        + latestVersion (string) - The latest version available for the specified package
        + latestVersionPublishedDate (string) - The timestamp for when the latest version of the specified package was published.
        + firstPublishedDate (string) - The timestamp for when the specified package was first published.
        + isDeprecated (boolean) - True if the latest version of the package is marked as deprecated; False otherwise.
        + deprecatedVersions (array[string]) - The numbers for those versions that are marked as deprecated
        + dependenciesWithIssues (array[string]) - The identifiers of dependencies with issues that are depended upon as a result of this dependency
        + type (string, required) - The package type of the dependency
        + licenses (array, fixed-type, required) - The licenses of the dependency
            + (object)
                + id (string, required) - The identifier of the license
                + title (string, required) - The title of the license
                + license (string, required) - The type of the license
        + projects (array, fixed-type, required) - The projects which depend on the dependency
            + (object)
                + id (string, required) - The identifier of the project
                + name (string, required) - The name of the project
+ total (number) - The number of results returned

## Dependencies Filters
+ filters (object)
    + languages (array) - The type of languages to filter the results by
        + node (string) - Include issues which are for NodeJS projects (npm or yarn package managers)
        + ruby (string) - Include issues which are for Ruby projects (rubygems package manager)
        + java (string) - Include issues which are for Java projects (maven or gradle)
    + projects (array) - The list of project IDs to filter the results by
    + dependencies (array) - The list of dependency IDs to filter the results by
    + licenses (array) - The list of license IDs to filter the results by
    + depStatus (string) - Status of the dependency. Requires reporting entitlement. Options: `deprecated` - Include only deprecated packages; `notDeprecated` - Include all packages that are not marked as deprecated; `any` - Include all packages (default)
# Group Licenses
The licenses which the packages/modules in your projects use.

## Licenses By Organisation [/org/{orgId}/licenses{?sortBy,order}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID to list projects for. The `API_KEY` must have access to this organisation.
    + sortBy: `license` (enum[string], optional) - The field to sort results by.
        + Default: `license`
        + Members
            + `license`
            + `dependencies`
            + `projects`
    + order (enum[string], optional) - The direction to sort results by.
        + Default: `asc`
        + Members
            + `asc`
            + `desc`

### List All Licenses [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Licenses Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Licenses)

    + Body

            {
                "results": [
                    {
                        "id": "MIT",
                        "dependencies": [
                            {
                                "id": "accepts@1.0.0",
                                "name": "accepts",
                                "version": "1.0.0",
                                "packageManager": "npm"
                            }
                        ],
                        "projects": [
                            {
                                "name": "atokeneduser/goof",
                                "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545"
                            }
                        ]
                    }
                ],
                "total": 1
            }

# Data Structures

## Licenses (object)
+ results (array, fixed-type, required) - A list of licenses
    + (object, required)
        + id (string, required) - The identifier of the license
        + dependencies (array, fixed-type, required) - The dependencies of projects in the organisation which have the license
            + (object)
                + id (string, required) - The identifier of the package
                + name (string, required) - The name of the package
                + version (string, required) - The version of the package
                + packageManager (string, required) - The package manager of the dependency
        + projects (array, fixed-type, required) - The projects which contain the license
            + (object)
                + id (string, required) - The identifier of the project
                + name (string, required) - The name of the project
+ total (number) - The number of results returned

## Licenses Filters
+ filters (object)
    + languages (array) - The type of languages to filter the results by
        + node (string) - Include issues which are for NodeJS projects (npm or yarn package managers)
        + ruby (string) - Include issues which are for Ruby projects (rubygems package manager)
        + java (string) - Include issues which are for Java projects (maven or gradle)
    + projects (array) - The list of project IDs to filter the results by
    + dependencies (array) - The list of dependency IDs to filter the results by
    + licenses (array) - The list of license IDs to filter the results by
# Group Entitlements
Entitlements are specific abilities an organisation has enabled.

## Entitlements By Organisation [/org/{orgId}/entitlements]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID to list entitlements for. The `API_KEY` must have access to this organisation.

### List All Entitlements [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY


+ Response 200 (application/json; charset=utf-8)

    + Body

            {
                "licenses": true,
                "reports": true
            }


## A specific entitlement by organisation [/org/{orgId}/entitlement/{entitlementKey}]
It is possible to query an organisation for a specific entitlement, getting its value.

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organisation ID to query the entitlement for. The `API_KEY` must have access to this organisation.
    + entitlementKey: `reports` (string, required) - The entitlement to query.

### Get an organisation's entitlement value [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY


+ Response 200 (application/json; charset=utf-8)

    + Body

            true
# Group Test
Test a package for issues with Snyk.

## Maven [/test/maven/{groupId}/{artifactId}/{version}{?org,repository}]
Test for issues in Maven files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organisation to test the package with. See "The Snyk Organisation For A Request" above.
    + repository: `https://repo1.maven.org/maven2` (string, optional) - The Maven repository hosting this package. The default value is Maven Central. More than one value is supported, in order.

### Test For Issues In A Public Package By Group ID, Artifact ID and Version  [GET /test/maven/{groupId}/{artifactId}/{version}{?org,repository}]
You can test `maven` packages for issues according to their [coordinates](https://maven.apache.org/pom.html#Maven_Coordinates): group ID, artifact ID and version. The repository hosting the package may also be customized (see the `repository` query parameter).

+ Parameters
    + groupId: `org.apache.flex.blazeds` (string, required) - The package's group ID.
    + artifactId: `blazeds` (string, required) - The package's artifact ID.
    + version: `4.7.2` (string, required) - The package version to test.


+ Request (application/json)
    + Headers

            Authorization: token API_KEY



+ Response 200 (application/json; charset=utf-8)

        {
            "ok": false,
            "issues": {
              "vulnerabilities": [
                {
                  "id": "SNYK-JAVA-ORGAPACHEFLEXBLAZEDS-31455",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEFLEXBLAZEDS-31455",
                  "title": "Arbitrary Code Execution",
                  "type": "vuln",
                  "package": "org.apache.flex.blazeds:blazeds",
                  "version": "4.7.2",
                  "severity": "high",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": "[,4.7.3)",
                    "unaffected": "[4.7.3,]"
                  },
                  "publicationTime": "2017-08-09T14:17:08.212Z",
                  "disclosureTime": "2017-04-25T21:00:00.000Z",
                  "isUpgradable": false,
                  "isPatchable": false,
                  "identifiers": {
                    "CWE": [
                      "CWE-502"
                    ],
                    "CVE": [
                      "CVE-2017-5641"
                    ]
                  },
                  "credit": [
                    "Markus Wulftange"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  "cvssScore": 9.8,
                  "patches": [],
                  "upgradePath": []
                }
              ],
              "licenses": []
            },
            "dependencyCount": 1,
            "org": {
              "name": "atokeneduser",
              "id": "689ce7f9-7943-4a71-b704-2ba575f01089"
            },
            "licensesPolicy": null,
            "packageManager": "maven"
        }



### Test Maven File [POST /test/maven{?org,repository}]
You can test your Maven packages for issues according to their manifest file using this action. It takes a JSON object containing a the "target" `pom.xml`.

Additional manifest files, if they are needed, like parent `pom.xml` files, child poms, etc., according the the definitions in the target `pom.xml` file, should be supplied in the `additional` body parameter.

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Maven Request Payload)


+ Response 200 (application/json; charset=utf-8)


        {
            "ok":false,
            "issues":{
                "vulnerabilities":[
                    {
                        "id": "SNYK-JAVA-AXIS-30071",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-AXIS-30071",
                        "title": "Improper Validation of Certificate with Host Mismatch",
                        "type": "vuln",
                        "package": "axis:axis",
                        "version": "1.4",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                            "vulnerable": "(,1.4]",
                            "unaffected": "[,0.0.0)"
                        },
                        "publicationTime": "2014-08-18T16:51:53.000Z",
                        "disclosureTime": "2014-08-18T16:51:53.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-297"
                          ],
                          "CVE": [
                            "CVE-2014-3596"
                          ]
                        },
                        "credit": [
                          "David Jorm",
                          "Arun Neelicattu"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "cvssScore": 5.4,
                        "upgradePath": []
                    },
                    {
                        "id": "SNYK-JAVA-AXIS-30189",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-AXIS-30189",
                        "title": "Man-in-the-Middle (MitM)",
                        "type": "vuln",
                        "package": "axis:axis",
                        "version": "1.4",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "(,1.4]",
                          "unaffected": ""
                        },
                        "publicationTime": "2017-03-13T08:00:21.585Z",
                        "disclosureTime": "2014-06-17T03:59:52.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-20"
                          ],
                          "CVE": [
                            "CVE-2012-5784"
                          ]
                        },
                        "credit": [
                          "Alberto Fernández"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "cvssScore": 5.4,
                        "upgradePath": []
                      },
                      {
                        "id": "SNYK-JAVA-ORGAPACHEZOOKEEPER-31035",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEZOOKEEPER-31035",
                        "title": "Insufficiently Protected Credentials",
                        "type": "vuln",
                        "package": "org.apache.zookeeper:zookeeper",
                        "version": "3.5",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "[3.3.0,3.4.7), [3.5,3.5.1)",
                          "unaffected": ""
                        },
                        "publicationTime": "2016-10-05T08:19:32.697Z",
                        "disclosureTime": "2016-10-05T08:19:32.697Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-522"
                          ],
                          "CVE": [
                            "CVE-2014-0085"
                          ]
                        },
                        "credit": [
                          "Unknown"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "cvssScore": 4,
                        "upgradePath": []
                      },
                      {
                        "id": "SNYK-JAVA-ORGAPACHEZOOKEEPER-31428",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEZOOKEEPER-31428",
                        "title": "Denial of Service (DoS)",
                        "type": "vuln",
                        "package": "org.apache.zookeeper:zookeeper",
                        "version": "3.5",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "[,3.4.10), [3.5,3.5.3)",
                          "unaffected": ""
                        },
                        "publicationTime": "2017-05-21T07:52:38.983Z",
                        "disclosureTime": "2017-02-15T06:56:48.802Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [],
                          "CVE": [
                            "CVE-2017-5637"
                          ]
                        },
                        "credit": [
                          "Unknown"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                        "cvssScore": 5.3,
                        "upgradePath": []
                      }
                ],
                "licenses":[
                    {
                        "id": "snyk:lic:maven:org.aspectj:aspectjweaver:EPL-1.0",
                        "url": "https://snyk.io/vuln/snyk:lic:maven:org.aspectj:aspectjweaver:EPL-1.0",
                        "title": "EPL-1.0 license",
                        "type": "license",
                        "package": "org.aspectj:aspectjweaver",
                        "version": "1.8.2",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                            "vulnerable": [
                                "[0,]"
                            ]
                        }
                    }
                ]
            },
            "dependencyCount": 9,
            "org": {
                "name": "mySnykOrganisation",
                "id": "b94596b8-9d3e-45ae-ac1d-2bf7fa83d848"
            },
            "licensesPolicy": {
                "severities": {
                    "0BSD": "low",
                    "MS-RL": "medium",
                    "EPL-1.0": "medium",
                    "GPL-2.0": "low",
                    "GPL-3.0": "high",
                    "MPL-1.1": "medium",
                    "MPL-2.0": "medium",
                    "AGPL-1.0": "low",
                    "AGPL-3.0": "low",
                    "CDDL-1.0": "medium",
                    "LGPL-2.0": "medium",
                    "LGPL-2.1": "medium",
                    "LGPL-3.0": "medium",
                    "CPOL-1.02": "low",
                    "LGPL-2.1+": "medium",
                    "LGPL-3.0+": "medium",
                    "SimPL-2.0": "high",
                    "Artistic-1.0": "medium",
                    "Artistic-2.0": "medium"
                }
            },
            "packageManager": "maven"
        }


## npm [/test/npm{?org}]
Test for issues in npm files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organisation to test the package with. See "The Snyk Organisation For A Request" above.

### Test For Issues In A Public Package By Name and Version  [GET /test/npm/{packageName}/{version}{?org}]
You can test `npm` packages for issues according to their name and version.

+ Parameters
    + packageName: `ms` (string, required) - The package name. For scoped packages, **must** be url-encoded, so to test "@angular/core" version 4.3.2, one should `GET /test/npm/%40angular%2Fcore/4.3.2`.
    + version: `0.7.0` (string, required) - The Package version to test.


+ Request (application/json)
    + Headers

            Authorization: token API_KEY



+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "npm:ms:20151024",
                "url": "https://snyk.io/vuln/npm:ms:20151024",
                "title": "Regular Expression Denial of Service (DoS)",
                "type": "vuln",
                "description": "## Overview\n[`ms`](https://www.npmjs.com/package/ms) is a tiny milisecond conversion utility.\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) due to an incomplete fix for previously reported vulnerability [npm:ms:20151024](https://snyk.io/vuln/npm:ms:20151024). The fix limited the length of accepted input string to 10,000 characters, and turned to be insufficient making it possible to block the event loop for 0.3 seconds (on a typical laptop) with a specially crafted string passed to `ms()` function.\n\n*Proof of concept*\n```js\nms = require('ms');\nms('1'.repeat(9998) + 'Q') // Takes about ~0.3s\n```\n\n**Note:** Snyk's patch for this vulnerability limits input length to 100 characters. This new limit was deemed to be a breaking change by the author.\nBased on user feedback, we believe the risk of breakage is _very_ low, while the value to your security is much greater, and therefore opted to still capture this change in a patch for earlier versions as well.  Whenever patching security issues, we always suggest to run tests on your code to validate that nothing has been broken.\n\nFor more information on `Regular Expression Denial of Service (ReDoS)` attacks, go to our [blog](https://snyk.io/blog/redos-and-catastrophic-backtracking/).\n\n## Disclosure Timeline\n- Feb 9th, 2017 - Reported the issue to package owner.\n- Feb 11th, 2017 - Issue acknowledged by package owner.\n- April 12th, 2017 - Fix PR opened by Snyk Security Team.\n- May 15th, 2017 - Vulnerability published.\n- May 16th, 2017 - Issue fixed and version `2.0.0` released.\n- May 21th, 2017 - Patches released for versions `>=0.7.1, <=1.0.0`.\n\n## Remediation\nUpgrade `ms` to version 2.0.0 or higher.\n\n## References\n- [GitHub PR](https://github.com/zeit/ms/pull/89)\n- [GitHub Commit](https://github.com/zeit/ms/pull/89/commits/305f2ddcd4eff7cc7c518aca6bb2b2d2daad8fef)\n",
                "from": [
                  "ms@0.7.0"
                ],
                "package": "ms",
                "version": "0.7.0",
                "severity": "medium",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": "<=0.7.0",
                  "unaffected": ">0.7.0"
                },
                "publicationTime": "2015-11-06T02:09:36.187Z",
                "disclosureTime": "2015-10-24T20:39:59.852Z",
                "isUpgradable": true,
                "isPatchable": true,
                "identifiers": {
                  "CWE": [
                    "CWE-400"
                  ],
                  "CVE": [
                    "CVE-2015-8315"
                  ],
                  "NSP": 46,
                  "ALTERNATIVE": [
                    "SNYK-JS-MS-10064"
                  ]
                },
                "credit": [
                  "Adam Baldwin"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                "cvssScore": 5.3,
                "patches": [
                  {
                    "urls": [
                      "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/ms/20151024/ms_20151024_0_0_48701f029417faf65e6f5e0b61a3cebe5436b07b.patch"
                    ],
                    "version": "=0.7.0",
                    "modificationTime": "2015-10-24T20:39:59.852Z",
                    "comments": [],
                    "id": "patch:npm:ms:20151024:0"
                  },
                  {
                    "urls": [
                      "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/ms/20151024/ms_20151024_1_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk.patch"
                    ],
                    "version": "<0.7.0 >=0.6.0",
                    "modificationTime": "2015-10-24T20:39:59.852Z",
                    "comments": [],
                    "id": "patch:npm:ms:20151024:1"
                  },
                  {
                    "urls": [
                      "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/ms/20151024/ms_20151024_2_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk2.patch"
                    ],
                    "version": "<0.6.0 >0.3.0",
                    "modificationTime": "2015-10-24T20:39:59.852Z",
                    "comments": [],
                    "id": "patch:npm:ms:20151024:2"
                  },
                  {
                    "urls": [
                      "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/ms/20151024/ms_20151024_3_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk3.patch"
                    ],
                    "version": "=0.3.0",
                    "modificationTime": "2015-10-24T20:39:59.852Z",
                    "comments": [],
                    "id": "patch:npm:ms:20151024:3"
                  },
                  {
                    "urls": [
                      "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/ms/20151024/ms_20151024_4_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk4.patch"
                    ],
                    "version": "=0.2.0",
                    "modificationTime": "2015-10-24T20:39:59.852Z",
                    "comments": [],
                    "id": "patch:npm:ms:20151024:4"
                  },
                  {
                    "urls": [
                      "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/ms/20151024/ms_20151024_5_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk5.patch"
                    ],
                    "version": "=0.1.0",
                    "modificationTime": "2015-10-24T20:39:59.852Z",
                    "comments": [],
                    "id": "patch:npm:ms:20151024:5"
                  }
                ],
                "upgradePath": [
                  false,
                  "ms@0.7.1"
                ]
              },
              {
                "id": "npm:ms:20170412",
                "url": "https://snyk.io/vuln/npm:ms:20170412",
                "title": "Regular Expression Denial of Service (ReDoS)",
                "type": "vuln",
                "description": "## Overview\n[`ms`](https://www.npmjs.com/package/ms) is a tiny milisecond conversion utility.\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) due to an incomplete fix for previously reported vulnerability [npm:ms:20151024](https://snyk.io/vuln/npm:ms:20151024). The fix limited the length of accepted input string to 10,000 characters, and turned to be insufficient making it possible to block the event loop for 0.3 seconds (on a typical laptop) with a specially crafted string passed to`ms()` function.\n\n*Proof of concept*\n```js\nms = require('ms');\nms('1'.repeat(9998) + 'Q') // Takes about ~0.3s\n```\n\n**Note:** Snyk's patchfor this vulnerability limits input length to 100 characters. This new limit was deemed to be a breaking change by the author.\nBased on user feedback, we believe the risk of breakage is _very_ low, while the value to your security is much greater, and therefore opted to still capture this change in a patch for earlier versions as well.  Whenever patching security issues, we always suggest to run tests on your code to validate that nothing has been broken.\n\nFor more information on `Regular Expression Denial of Service (ReDoS)` attacks, go to our [blog](https://snyk.io/blog/redos-and-catastrophic-backtracking/).\n\n## Disclosure Timeline\n- Feb 9th, 2017 - Reported the issue to package owner.\n- Feb 11th, 2017 - Issue acknowledged by package owner.\n- April 12th, 2017 - Fix PR opened by Snyk Security Team.\n- May 15th, 2017 - Vulnerability published.\n- May 16th, 2017- Issue fixed and version `2.0.0` released.\n- May 21th, 2017 - Patches released for versions `>=0.7.1, <=1.0.0`.\n\n## Remediation\nUpgrade `ms` to version 2.0.0 or higher.\n\n## References\n- [GitHub PR](https://github.com/zeit/ms/pull/89)\n- [GitHub Commit](https://github.com/zeit/ms/pull/89/commits/305f2ddcd4eff7cc7c518aca6bb2b2d2daad8fef)\n",
                "from": [
                  "ms@0.7.0"
                ],
                "package": "ms",
                "version": "0.7.0",
                "severity": "low",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "unaffected": ">=2.0.0",
                  "vulnerable": "<2.0.0"
                },
                "publicationTime": "2017-05-15T06:02:45.497Z",
                "disclosureTime": "2017-04-11T21:00:00.000Z",
                "isUpgradable": true,
                "isPatchable": false,
                "identifiers": {
                  "CWE": [
                    "CWE-400"
                  ],
                  "CVE": [],
                  "ALTERNATIVE": [
                    "SNYK-JS-MS-10509"
                  ]
                },
                "credit": [
                  "Snyk Security Research Team"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                "cvssScore": 3.7,
                "patches": [
                  {
                    "urls": [
                      "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/ms/20170412/ms_100.patch"
                    ],
                    "version": "=1.0.0",
                    "modificationTime": "2017-05-16T10:12:18.990Z",
                    "comments": [],
                    "id": "patch:npm:ms:20170412:0"
                  },
                  {
                    "urls": [
                      "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/ms/20170412/ms_072-073.patch"
                    ],
                    "version": "=0.7.2 || =0.7.3",
                    "modificationTime": "2017-05-16T10:12:18.990Z",
                    "comments": [],
                    "id": "patch:npm:ms:20170412:1"
                  },
                  {
                    "urls": [
                      "https://s3.amazonaws.com/snyk-rules-pre-repository/snapshots/master/patches/npm/ms/20170412/ms_071.patch"
                    ],
                    "version": "=0.7.1",
                    "modificationTime": "2017-05-16T10:12:18.990Z",
                    "comments": [],
                    "id": "patch:npm:ms:20170412:2"
                  }
                ],
                "upgradePath": [
                  false,
                  "ms@2.0.0"
                ]
              }
            ],
            "licenses": []
          },
          "dependencyCount": 1,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "npm"
        }


### Test package.json File [POST /test/npm{?org}]
You can test your npm packages for issues according to their manifest file using this action. It takes a JSON object containing a the "target" `package.json`.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (npm Request Payload)


+ Response 200 (application/json; charset=utf-8)


        {
            "ok":false,
            "issues":{
                "vulnerabilities":[],
                "licenses":[]
            },
            "dependencyCount":51,
            "org":"deebugger",
            "licensesPolicy":{"severities":{"MIT":"high","MS-RL":"medium","EPL-1.0":"medium","GPL-2.0":"high","GPL-3.0":"high","MPL-1.1":"medium","MPL-2.0":"medium","AGPL-1.0":"high","AGPL-3.0":"high","CDDL-1.0":"medium","LGPL-2.0":"medium","LGPL-2.1":"medium","LGPL-3.0":"medium","CPOL-1.02":"high","LGPL-2.1+":"medium","LGPL-3.0+":"medium","SimPL-2.0":"high","Artistic-1.0":"medium","Artistic-2.0":"medium"}},
            "isPrivate":true,
            "packageManager":"maven",
            "summary":"30 vulnerable dependency paths"
        }


## rubygems [/test/rubygems{?org}]
Test for issues in rubygems packages and applications.

+ Parameters
    + org: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, optional) - The organisation to test the package with. See "The Snyk Organisation For A Request" above.

### Test For Issues In A Public Gem By Name and Version  [GET /test/rubygems/{gemName}/{version}{?org}]
You can test `rubygems` packages for issues according to their name and version.

+ Parameters
    + gemName: `rails-html-sanitizer` (string, required) - The gem name.
    + version: `1.0.3` (string, required) - The gem version to test.


+ Request (application/json)
    + Headers

            Authorization: token API_KEY



+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-RUBY-NOKOGIRI-20299",
                "url": "https://snyk.io/vuln/SNYK-RUBY-NOKOGIRI-20299",
                "title": "XML External Entity (XXE) Injection",
                "type": "vuln",
                "description": "## Overview\n[nokogiri](https://rubygems.org/gems/nokogiri) is an HTML, XML, SAX, and Reader parser, with the ability to search documents via XPath or CSS3 selectors.\nAffected versions of this Gem are vulnerable to XML External Entity (XXE) attacks when opting into the `DTDLOAD` option and opting out of the `NONET` option.\n\n## Details\n`Nokogiri` is affected by series of vulnerabilities in libxml2 and libxslt, which are libraries it depends on. When handling the expansion of XML external entities (XXE) in libxml2, you can specify documents to be read. Opting into the `DTDLOAD` option and opting out of the `NONET` option in `Nokogiri` allows unknown documents to be loaded from the network. This can be used by attackers to load specially crafted XML documents on an internal XML parsing service and may lead to unauthorized disclosure of potentially sensitive information.\n\n**Note:** This vulnerability exists also in versions `< 1.5.4` regardless of the options opted into or out of. See information [here](https://snyk.io/vuln/SNYK-RUBY-NOKOGIRI-20298)\n\n## Remediation\nNokogiri suggests not to opt-out of `NONET` unless only trusted documents are being parsed.\nThere currently is no fix in libxml2 as of September 17th, 2017.\n`Nokogiri` will be waiting for a fix upstream to update.\n\n## Disclosure Timeline\n- January 11th, 2017 - Reported the issue to [Mike Dalessio](https://github.com/flavorjones) of Nokogiri Core.\n- January 11th, 2017 - Issue triaged and acknowledged by [Mike Dalessio](https://github.com/flavorjones) of Nokogiri Core.\n\n## References\n- [GitHub Issue](https://github.com/sparklemotion/nokogiri/issues/1582)\n- [CVE-2016-9318](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9318)\n",
                "from": [
                  "rails-html-sanitizer@1.0.3",
                  "loofah@2.2.2",
                  "nokogiri@1.8.2"
                ],
                "package": "nokogiri",
                "version": "1.8.2",
                "severity": "high",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "unaffected": [
                    "< 1.5.4"
                  ],
                  "vulnerable": [
                    ">= 1.5.4"
                  ]
                },
                "publicationTime": "2017-01-16T21:00:00.000Z",
                "disclosureTime": "2017-01-11T21:00:00.000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "identifiers": {
                  "CWE": [
                    "CWE-611"
                  ],
                  "CVE": []
                },
                "credit": [
                  "Snyk Security Research Team"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvssScore": 7.3,
                "upgradePath": []
              },
              {
                "id": "SNYK-RUBY-RAILSHTMLSANITIZER-22025",
                "url": "https://snyk.io/vuln/SNYK-RUBY-RAILSHTMLSANITIZER-22025",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n[rails-html-sanitizer](https://github.com/rails/rails-html-sanitizer)\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS). The gem allows non-whitelisted attributes to be present in sanitized output when input with specially-crafted HTML fragments, and these attributes can lead to an XSS attack on target applications.\n\nThis issue is similar to [CVE-2018-8048](https://snyk.io/vuln/SNYK-RUBY-LOOFAH-22023) in Loofah.\n\n## Details\nCross-Site Scripting (XSS) attacks occur when an attacker tricks a user’s browser to execute malicious JavaScript code in the context of a victim’s domain. Such scripts can steal the user’s session cookies for the domain, scrape or modify its content, and perform or modify actions on the user’s behalf, actions typically blocked by the browser’s Same Origin Policy.\n\nThese attacks are possible by escaping the context of the web application and injecting malicious scripts in an otherwise trusted website. These scripts can introduce additional attributes (say, a \"new\" option in a dropdown list or a new link to a malicious site) and can potentially execute code on the clients side, unbeknown to the victim. This occurs when characters like \\< \\> \\\" \\' are not escaped properly.\n\nThere are a few types of XSS:\n- **Persistent XSS** is an attack in which the malicious code persists into the web app’s database.\n- **Reflected XSS** is an which the website echoes back a portion of the request. The attacker needs to trick the user into clicking a malicious link (for instance through a phishing email or malicious JS on another page), which triggers the XSS attack.\n- **DOM-based XSS** is an that occurs purely in the browser when client-side JavaScript echoes back a portion of the URL onto the page. DOM-Based XSS is notoriously hard to detect, as the server never gets a chance to see the attack taking place.\n\n\n## Remediation\nUpgrade `rails-html-sanitizer` to version 1.0.4 or higher.\n\n## References\n- [Ruby on Rails Security Google Forum](https://groups.google.com/d/msg/rubyonrails-security/tP7W3kLc5u4/uDy2Br7xBgAJ)\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-3741)\n",
                "from": [
                  "rails-html-sanitizer@1.0.3"
                ],
                "package": "rails-html-sanitizer",
                "version": "1.0.3",
                "severity": "medium",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "unaffected": [
                    ">=1.0.4"
                  ],
                  "vulnerable": [
                    "<1.0.4"
                  ]
                },
                "publicationTime": "2018-03-27T07:42:10.777Z",
                "disclosureTime": "2018-03-22T21:46:15.453Z",
                "isUpgradable": true,
                "isPatchable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-3741"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Kaarlo Haikonen"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                "cvssScore": 6.5,
                "patches": [],
                "upgradePath": [
                  "rails-html-sanitizer@1.0.4"
                ]
              }
            ],
            "licenses": []
          },
          "dependencyCount": 5,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "rubygems"
        }


### Test Gemfile.lock File [POST /test/rubygems{?org}]
You can test your rubygems applications for issues according to their lockfile using this action. It takes a JSON object containing a the "target" `Gemfile.lock`.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (rubygems Request Payload)


+ Response 200 (application/json; charset=utf-8)

        {
          "ok": true,
          "issues": {
            "vulnerabilities": [],
            "licenses": []
          },
          "dependencyCount": 0,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "rubygems"
        }



## Gradle [/test/gradle{?org,repository}]
Test for issues in Gradle files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organisation to test the package with. See "The Snyk Organisation For A Request" above.
    + repository: `https://repo1.maven.org/maven2` (string, optional) - The repository hosting this package. The default value is Maven Central. More than one value is supported, in order.

### Test For Issues In A Public Package By Group, Name and Version  [GET /test/gradle/{group}/{name}/{version}{?org,repository}]
You can test `gradle` packages for issues according to their group, name and version. This is done via the maven endpoint (for Java), since the packages are hosted on maven central or a compatible repository. See "Maven" above for details.

+ Parameters
    + group: `org.apache.flex.blazeds` (string, required) - The package's group ID.
    + name: `blazeds` (string, required) - The package's artifact ID.
    + version: `4.7.2` (string, required) - The package version to test.


+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY


+ Response 303 (text/plain; charset=utf-8)
    + Headers

            Location: http://snyk.io/api/v1/test/maven/org.apache.flex.blazeds/blazeds/4.7.2


    + Body

            See Other. Redirecting to http://snyk.io/api/v1/test/maven/org.apache.flex.blazeds/blazeds/4.7.2



### Test Gradle File [POST /test/gradle{?org,repository}]
You can test your Gradle packages for issues according to their manifest file using this action. It takes a JSON object containing the "target" `build.gradle`.


+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Gradle Request Payload)


+ Response 200 (application/json; charset=utf-8)


        {
            "ok":false,
            "issues":{
                "vulnerabilities":[
                    {
                        "id": "SNYK-JAVA-AXIS-30071",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-AXIS-30071",
                        "title": "Improper Validation of Certificate with Host Mismatch",
                        "type": "vuln",
                        "package": "axis:axis",
                        "version": "1.4",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "(,1.4]",
                          "unaffected": "[,0.0.0)"
                        },
                        "publicationTime": "2014-08-18T16:51:53.000Z",
                        "disclosureTime": "2014-08-18T16:51:53.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-297"
                          ],
                          "CVE": [
                            "CVE-2014-3596"
                          ]
                        },
                        "credit": [
                          "David Jorm",
                          "Arun Neelicattu"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "cvssScore": 5.4,
                        "upgradePath": []
                    },
                    {
                        "id": "SNYK-JAVA-AXIS-30189",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-AXIS-30189",
                        "title": "Man-in-the-Middle (MitM)",
                        "type": "vuln",
                        "package": "axis:axis",
                        "version": "1.4",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "(,1.4]",
                          "unaffected": ""
                        },
                        "publicationTime": "2017-03-13T08:00:21.585Z",
                        "disclosureTime": "2014-06-17T03:59:52.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-20"
                          ],
                          "CVE": [
                            "CVE-2012-5784"
                          ]
                        },
                        "credit": [
                          "Alberto Fernández"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "cvssScore": 5.4,
                        "upgradePath": []
                    }
                ],
                "licenses":[]
            },
            "dependencyCount": 7,
            "org": {
                "name": "mySnykOrganisation",
                "id": "b94596b8-9d3e-45ae-ac1d-2bf7fa83d848"
            },
            "licensesPolicy": {
                "severities": {
                    "0BSD": "low",
                    "MS-RL": "medium",
                    "EPL-1.0": "medium",
                    "GPL-2.0": "low",
                    "GPL-3.0": "high",
                    "MPL-1.1": "medium",
                    "MPL-2.0": "medium",
                    "AGPL-1.0": "low",
                    "AGPL-3.0": "low",
                    "CDDL-1.0": "medium",
                    "LGPL-2.0": "medium",
                    "LGPL-2.1": "medium",
                    "LGPL-3.0": "medium",
                    "CPOL-1.02": "low",
                    "LGPL-2.1+": "medium",
                    "LGPL-3.0+": "medium",
                    "SimPL-2.0": "high",
                    "Artistic-1.0": "medium",
                    "Artistic-2.0": "medium"
                }
            },
            "packageManager": "gradle"
        }



## sbt [/test/sbt{?org,repository}]
Test for issues in sbt files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organisation to test the package with. See "The Snyk Organisation For A Request" above.
    + repository: `https://repo1.maven.org/maven2` (string, optional) - The repository hosting this package. The default value is Maven Central. More than one value is supported, in order.

### Test For Issues In A Public Package By Group ID, Artifact ID and Version  [GET /test/sbt/{groupId}/{artifactId}/{version}{?org,repository}]
You can test `sbt` packages for issues according to their group ID, artifact ID and version. This is done via the maven endpoint (for Java), since the packages are hosted on maven central or a compatible repository. See "Maven" above for details.

+ Parameters
    + groupId: `org.apache.flex.blazeds` (string, required) - The package's group ID.
    + artifactId: `blazeds` (string, required) - The package's artifact ID.
    + version: `4.7.2` (string, required) - The package version to test.


+ Request (application/json)
    + Headers

            Authorization: token API_KEY



+ Response 303 (text/plain; charset=utf-8)
    + Headers

            Location: http://snyk.io/api/v1/test/maven/org.apache.flex.blazeds/blazeds/4.7.2


    + Body

            See Other. Redirecting to http://snyk.io/api/v1/test/maven/org.apache.flex.blazeds/blazeds/4.7.2



### Test sbt File [POST /test/sbt{?org,repository}]
You can test your `sbt` packages for issues according to their manifest file using this action. It takes a JSON object containing a the "target" `build.sbt`.

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (sbt Request Payload)


+ Response 200 (application/json; charset=utf-8)


        {
            "ok":false,
            "issues":{
                "vulnerabilities":[
                    {
                        "id": "SNYK-JAVA-COMNING-30317",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-COMNING-30317",
                        "title": "Insufficient Verification of Data Authenticity",
                        "type": "vuln",
                        "package": "com.ning:async-http-client",
                        "version": "1.8.10",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "[,1.9)",
                          "unaffected": ""
                        },
                        "publicationTime": "2017-03-28T08:29:28.375Z",
                        "disclosureTime": "2015-06-25T16:01:27.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-345"
                          ],
                          "CVE": [
                            "CVE-2013-7397"
                          ]
                        },
                        "credit": [
                          "Unknown"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                        "cvssScore": 4.3,
                        "upgradePath": []
                      },
                      {
                        "id": "SNYK-JAVA-COMNING-30318",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-COMNING-30318",
                        "title": "Insufficient Verification of Data Authenticity",
                        "type": "vuln",
                        "package": "com.ning:async-http-client",
                        "version": "1.8.10",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "[,1.9.0)",
                          "unaffected": ""
                        },
                        "publicationTime": "2017-03-28T08:29:28.445Z",
                        "disclosureTime": "2015-06-25T16:10:20.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-345"
                          ],
                          "CVE": [
                            "CVE-2013-7398"
                          ]
                        },
                        "credit": [
                          "Unknown"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                        "cvssScore": 4.3,
                        "upgradePath": []
                      },
                      {
                        "id": "SNYK-JAVA-IONETTY-30430",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-IONETTY-30430",
                        "title": "Information Disclosure",
                        "type": "vuln",
                        "package": "io.netty:netty",
                        "version": "3.9.2.Final",
                        "severity": "low",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "[3.3,3.9.8.Final), [3.10,3.10.3.Final), [4.0,4.0.28.Final), [4.1,4.1.0.Beta5)",
                          "unaffected": ""
                        },
                        "publicationTime": "2015-04-08T21:44:31.000Z",
                        "disclosureTime": "2015-04-08T21:44:31.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-200"
                          ],
                          "CVE": [
                            "CVE-2015-2156"
                          ]
                        },
                        "credit": [
                          "Roman Shafigullin",
                          "Luca Carettoni",
                          "Mukul Khullar"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "cvssScore": 3.7,
                        "upgradePath": []
                      },
                      {
                        "id": "SNYK-JAVA-ORGAPACHEHTTPCOMPONENTS-30645",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEHTTPCOMPONENTS-30645",
                        "title": "Improper Input Validation",
                        "type": "vuln",
                        "package": "org.apache.httpcomponents:httpclient",
                        "version": "1.0.0-SNAPSHOT",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "(,4.2.2]",
                          "unaffected": ""
                        },
                        "publicationTime": "2014-09-07T12:18:36.000Z",
                        "disclosureTime": "2014-09-07T12:18:36.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-20"
                          ],
                          "CVE": [
                            "CVE-2012-6153"
                          ]
                        },
                        "credit": [
                          "Unknown"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                        "cvssScore": 4.3,
                        "upgradePath": []
                      },
                      {
                        "id": "SNYK-JAVA-ORGAPACHEHTTPCOMPONENTS-30647",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEHTTPCOMPONENTS-30647",
                        "title": "Denial of Service (DoS)",
                        "type": "vuln",
                        "package": "org.apache.httpcomponents:httpclient",
                        "version": "1.0.0-SNAPSHOT",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "[,4.3.6)",
                          "unaffected": ""
                        },
                        "publicationTime": "2015-10-19T07:26:52.000Z",
                        "disclosureTime": "2015-10-19T07:26:52.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-399"
                          ],
                          "CVE": [
                            "CVE-2015-5262"
                          ]
                        },
                        "credit": [
                          "Unknown"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
                        "cvssScore": 4.3,
                        "upgradePath": []
                      },
                      {
                        "id": "SNYK-JAVA-ORGECLIPSEJETTY-31116",
                        "url": "https://snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-31116",
                        "title": "Cryptographic Issues",
                        "type": "vuln",
                        "package": "org.eclipse.jetty:jetty-util",
                        "version": "1.0.0-SNAPSHOT",
                        "severity": "medium",
                        "language": "java",
                        "packageManager": "maven",
                        "semver": {
                          "vulnerable": "(,8.1.0.RC2]",
                          "unaffected": ""
                        },
                        "publicationTime": "2015-05-13T15:57:30.000Z",
                        "disclosureTime": "2015-05-13T15:57:30.000Z",
                        "isUpgradable": false,
                        "isPatchable": false,
                        "identifiers": {
                          "CWE": [
                            "CWE-310"
                          ],
                          "CVE": [
                            "CVE-2011-4461"
                          ]
                        },
                        "credit": [
                          "Unknown"
                        ],
                        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                        "cvssScore": 5.3,
                        "upgradePath": []
                      }

                ],
                "licenses": [
                    {
                      "id": "snyk:lic:maven:net.databinder.dispatch:dispatch-core_2.11:LGPL-3.0",
                      "url": "https://snyk.io/vuln/snyk:lic:maven:net.databinder.dispatch:dispatch-core_2.11:LGPL-3.0",
                      "title": "LGPL-3.0 license",
                      "type": "license",
                      "package": "net.databinder.dispatch:dispatch-core_2.11",
                      "version": "0.11.2",
                      "severity": "medium",
                      "language": "java",
                      "packageManager": "maven",
                      "semver": {
                        "vulnerable": [
                          "[0,]"
                        ]
                      }
                    },
                    {
                      "id": "snyk:lic:maven:net.sourceforge.cssparser:cssparser:GPL-3.0",
                      "url": "https://snyk.io/vuln/snyk:lic:maven:net.sourceforge.cssparser:cssparser:GPL-3.0",
                      "title": "GPL-3.0 license",
                      "type": "license",
                      "package": "net.sourceforge.cssparser:cssparser",
                      "version": "0.9.18",
                      "severity": "high",
                      "language": "java",
                      "packageManager": "maven",
                      "semver": {
                        "vulnerable": [
                          "[0.9.4,0.9.19)"
                        ]
                      }
                    },
                    {
                      "id": "snyk:lic:maven:net.sourceforge.htmlunit:htmlunit-core-js:MPL-2.0",
                      "url": "https://snyk.io/vuln/snyk:lic:maven:net.sourceforge.htmlunit:htmlunit-core-js:MPL-2.0",
                      "title": "MPL-2.0 license",
                      "type": "license",
                      "package": "net.sourceforge.htmlunit:htmlunit-core-js",
                      "version": "2.17",
                      "severity": "medium",
                      "language": "java",
                      "packageManager": "maven",
                      "semver": {
                        "vulnerable": [
                          ">=2.11"
                        ]
                      }
                    }
                ]
            },
            "dependencyCount": 58,
            "org": {
                "name": "mySnykOrganisation",
                "id": "b94596b8-9d3e-45ae-ac1d-2bf7fa83d848"
            },
            "licensesPolicy": {
                "severities": {
                    "0BSD": "low",
                    "MS-RL": "medium",
                    "EPL-1.0": "medium",
                    "GPL-2.0": "low",
                    "GPL-3.0": "high",
                    "MPL-1.1": "medium",
                    "MPL-2.0": "medium",
                    "AGPL-1.0": "low",
                    "AGPL-3.0": "low",
                    "CDDL-1.0": "medium",
                    "LGPL-2.0": "medium",
                    "LGPL-2.1": "medium",
                    "LGPL-3.0": "medium",
                    "CPOL-1.02": "low",
                    "LGPL-2.1+": "medium",
                    "LGPL-3.0+": "medium",
                    "SimPL-2.0": "high",
                    "Artistic-1.0": "medium",
                    "Artistic-2.0": "medium"
                }
            },
            "packageManager": "gradle"
        }


## pip [/test/pip{?org}]
Test for issues in pip files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organisation to test the package with. See "The Snyk Organisation For A Request" above.

### Test For Issues In A Public Package By Name and Version  [GET /test/pip/{packageName}/{version}{?org}]
You can test `pip` packages for issues according to their name and version.

+ Parameters
    + packageName: `rsa` (string, required) - The package name.
    + version: `3.1` (string, required) - The Package version to test.


+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY



+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-PYTHON-RSA-40377",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-RSA-40377",
                "title": "Improper Input Validation",
                "type": "vuln",
                "description": "## Overview\n[`rsa`](https://pypi.python.org/pypi/rsa) is a Pure-Python RSA implementation.\n\nThe verify function in the RSA package for Python (Python-RSA) before 3.3 allows attackers to spoof signatures with a small public exponent via crafted signature padding, aka a Berserk attack.\n\n## References\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-1494)\n- [Bitbucket PR](https://bitbucket.org/sybren/python-rsa/pull-requests/14/security-fix-bb06-attack-in-verify-by/diff)\n- [Bitbucket Commit](https://bitbucket.org/sybren/python-rsa/commits/0cbcc529926afd61c6df4f50cfc29971beafd2c2?at=default)\n",
                "from": [
                  "rsa@3.1"
                ],
                "package": "rsa",
                "version": "3.1",
                "severity": "medium",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": "[,3.3)",
                  "unaffected": ""
                },
                "publicationTime": "2015-12-15T00:27:53.061Z",
                "disclosureTime": "2015-12-15T00:27:53.061Z",
                "isUpgradable": false,
                "isPatchable": false,
                "identifiers": {
                  "CWE": [
                    "CWE-20"
                  ],
                  "CVE": [
                    "CVE-2016-1494"
                  ]
                },
                "credit": [
                  "Filippo Valsorda"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvssScore": 5.3,
                "upgradePath": []
              },
              {
                "id": "SNYK-PYTHON-RSA-40541",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-RSA-40541",
                "title": "Timing Attack",
                "type": "vuln",
                "description": "## Overview\n[`rsa`](https://pypi.python.org/pypi/rsa) is a Pure-Python RSA implementation.\n\nAffected versions of this package are vulnerable to Timing attacks.\n\n## References\n- [GitHub Issue](https://github.com/sybrenstuvel/python-rsa/issues/19)\n- [GitHub Commit](https://github.com/sybrenstuvel/python-rsa/commit/2310b34bdb530e0bad793d42f589c9f848ff181b)\n",
                "from": [
                  "rsa@3.1"
                ],
                "package": "rsa",
                "version": "3.1",
                "severity": "medium",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": "[3.0,3.4.0)",
                  "unaffected": ""
                },
                "publicationTime": "2013-11-15T02:34:45.265Z",
                "disclosureTime": "2013-11-15T02:34:45.265Z",
                "isUpgradable": false,
                "isPatchable": false,
                "identifiers": {
                  "CWE": [
                    "CWE-208"
                  ],
                  "CVE": []
                },
                "credit": [
                  "Manuel Aude Morales"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 5.3,
                "upgradePath": []
              },
              {
                "id": "SNYK-PYTHON-RSA-40542",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-RSA-40542",
                "title": "Authentication Bypass",
                "type": "vuln",
                "description": "## Overview\n[`rsa`](https://pypi.python.org/pypi/rsa) is a Pure-Python RSA implementation.\n\nAffected versions of this package are vulnerable to Authentication Bypass due to not implementing authentication encryption or use MACs to validate messages before decrypting public key encrypted messages.\n\n## References\n- [GitHub Issue](https://github.com/sybrenstuvel/python-rsa/issues/13)\n- [GitHub Commit](https://github.com/sybrenstuvel/python-rsa/commit/1681a0b2f84a4a252c71b87de870a2816de06fdf)\n",
                "from": [
                  "rsa@3.1"
                ],
                "package": "rsa",
                "version": "3.1",
                "severity": "high",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": "[3.0,3.4)",
                  "unaffected": ""
                },
                "publicationTime": "2012-12-07T03:15:00.052Z",
                "disclosureTime": "2012-12-07T03:15:00.052Z",
                "isUpgradable": false,
                "isPatchable": false,
                "identifiers": {
                  "CWE": [
                    "CWE-287"
                  ],
                  "CVE": []
                },
                "credit": [
                  "Sergio Lerner"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "upgradePath": []
              }
            ],
            "licenses": []
          },
          "dependencyCount": 2,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "pip"
        }



### Test requirements.txt File [POST /test/pip{?org}]
You can test your pip packages for issues according to their manifest file using this action. It takes a JSON object containing a the "target" `requirements.txt`.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (pip Request Payload)


+ Response 200 (application/json; charset=utf-8)


        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-PYTHON-OAUTH2-40013",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-OAUTH2-40013",
                "title": "Replay Attack",
                "type": "vuln",
                "description": "## Overview\r\n[`oauth2`](https://pypi.python.org/pypi/oauth2) is a library for OAuth version 1.9\r\nThe Server.verify_request function in SimpleGeo python-oauth2 does not check the nonce, which allows remote attackers to perform replay attacks via a signed URL.\r\n\r\n## Remediation\r\nUpgrade to version `1.5.211` or greater.\r\n\r\n## References\r\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2013-4346)\r\n- [Bugzilla redhat](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4346)\r\n- [GitHub Issue](https://github.com/simplegeo/python-oauth2/issues/129)\r\n",
                "from": [
                  "oauth2@1.5.211"
                ],
                "package": "oauth2",
                "version": "1.5.211",
                "severity": "medium",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": "(,1.5.211]",
                  "unaffected": ""
                },
                "publicationTime": "2013-02-05T12:31:58.000Z",
                "disclosureTime": "2013-02-05T12:31:58.000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "identifiers": {
                  "CWE": [
                    "CWE-310"
                  ],
                  "CVE": [
                    "CVE-2013-4346"
                  ]
                },
                "credit": [
                  "André Cruz"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:H/S:U/C:N/I:L/A:N",
                "cvssScore": 4.3,
                "upgradePath": []
              },
              {
                "id": "SNYK-PYTHON-OAUTH2-40014",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-OAUTH2-40014",
                "title": "Insecure Randomness",
                "type": "vuln",
                "description": "## Overview\r\n[`oauth2`](https://pypi.python.org/pypi/oauth2) is a library for OAuth version 1.9\r\n\r\nAffected versions of this package are vulnerable to Insecure Randomness.\r\nThe (1) make_nonce, (2) generate_nonce, and (3) generate_verifier functions in SimpleGeo python-oauth2 uses weak random numbers to generate nonces, which makes it easier for remote attackers to guess the nonce via a brute force attack.\r\n\r\n## Remediation\r\nUpgrade to version `1.5.211` or greater.\r\n\r\n## References\r\n- [Redhat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4347)\r\n- [GitHub Issue](https://github.com/simplegeo/python-oauth2/issues/9)\r\n- [Openwall](http://www.openwall.com/lists/oss-security/2013/09/12/7)\r\n- [GitHub PR](https://github.com/simplegeo/python-oauth2/pull/146)\r\n",
                "from": [
                  "oauth2@1.5.211"
                ],
                "package": "oauth2",
                "version": "1.5.211",
                "severity": "medium",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": "(,1.5.211]",
                  "unaffected": "[,0.0.0)"
                },
                "publicationTime": "2017-04-13T12:31:58.000Z",
                "disclosureTime": "2017-04-13T12:31:58.000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "identifiers": {
                  "CWE": [
                    "CWE-310"
                  ],
                  "CVE": [
                    "CVE-2013-4347"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:H/S:U/C:L/I:L/A:N",
                "cvssScore": 5.4,
                "upgradePath": []
              },
              {
                "id": "SNYK-PYTHON-SUPERVISOR-40610",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-SUPERVISOR-40610",
                "title": "Arbitrary Command Execution",
                "type": "vuln",
                "description": "## Overview\n[`supervisor`](https://pypi.python.org/pypi/supervisor/) is a client/server system that allows its users to monitor and control a number of processes on UNIX-like operating systems.\n\nAffected versions of the package are vulnerable to Arbitrary Command Execution. A vulnerability has been found where an authenticated client can send a malicious XML-RPC request to `supervisord` that will run arbitrary shell commands on the server. The commands will be run as the same user as `supervisord`. Depending on how `supervisord` has been configured, this may be root.\n\n## Details\n* `supervisord` is the server component and is responsible for starting child processes, responding to commands from clients, and other commands.\n* `supervisorctl` is the command line component, providing a shell-like interface to the features provided by `supervisord`.\n\n`supervisord` can be configured to run an HTTP server on a TCP socket and/or a Unix domain socket. This HTTP server is how `supervisorctl` communicates with `supervisord`. If an HTTP server has been enabled, it will always serve both HTML pages and an XML-RPC interface. A vulnerability has been found where an authenticated client can send a malicious XML-RPC request to `supervisord` that will run arbitrary shell commands on the server. The commands will be run as the same user as `supervisord`. Depending on how `supervisord` has been configured, this may be root.\nThis vulnerability can only be exploited by an authenticated client or if `supervisord` has been configured to run an HTTP server without authentication. If authentication has not been enabled, `supervisord` will log a message at the critical level every time it starts.\n\n## PoC by Maor Shwartz\n\nCreate a config file `supervisord.conf`:\n\n```conf\n[supervisord]\nloglevel = trace\n\n[inet_http_server]\nport = 127.0.0.1:9001\n\n[rpcinterface:supervisor]\nsupervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface\n```\n\nStart supervisord in the foreground with that config file:\n\n```\n$ supervisord -n -c supervisord.conf\n```\n\nIn a new terminal:\n\n```py\n$ python2\n>>> from xmlrpclib import ServerProxy\n>>> server = ServerProxy('http://127.0.0.1:9001/RPC2')\n>>> server.supervisor.supervisord.options.execve('/bin/sh', [], {})\n  ```\n\nIf the `supervisord` version is vulnerable, the `execve` will be executed and the `supervisord` process will be replaced with /bin/sh (or any other command given). If the `supervisord` version is not vulnerable, it will return an `UNKNOWN_METHOD` fault.\n\n\n## Remediation\nUpgrade `supervisor` to version 3.3.3 or higher.\n\n## References\n- [Github Issue](https://github.com/Supervisor/supervisor/issues/964)\n- [Github Commit 3.0.1](https://github.com/Supervisor/supervisor/commit/83060f3383ebd26add094398174f1de34cf7b7f0)\n- [Github Commit 3.1.4](https://github.com/Supervisor/supervisor/commit/dbe0f55871a122eac75760aef511efc3a8830b88)\n- [Github Commit 3.2.4](https://github.com/Supervisor/supervisor/commit/aac3c21893cab7361f5c35c8e20341b298f6462e)\n- [Github Commit 3.3.3](https://github.com/Supervisor/supervisor/commit/058f46141e346b18dee0497ba11203cb81ecb19e)\n",
                "from": [
                  "supervisor@3.1.0"
                ],
                "package": "supervisor",
                "version": "3.1.0",
                "severity": "high",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "unaffected": "",
                  "vulnerable": "[3.0a1,3.0.1), [3.1,3.1.4), [3.2,3.2.4), [3.3,3.3.3)"
                },
                "publicationTime": "2017-08-08T06:59:14.640Z",
                "disclosureTime": "2017-07-18T21:00:00.000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "identifiers": {
                  "CWE": [
                    "CWE-94"
                  ],
                  "CVE": [
                    "CVE-2017-11610"
                  ]
                },
                "credit": [
                  "Maor Shwartz"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 8.8,
                "patches": [],
                "upgradePath": []
              }
            ],
            "licenses": []
          },
          "dependencyCount": 4,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "pip"
        }


# Data Structures

## Vulnerability (object)
+ title (string) - The title of the vulnerability
+ credit (object) - The reporter of the vulnerability
+ description (string) - The description of the vulnerability
+ semver (SemverObject) - Versions affected by this issue
+ CVSSv3 (string) - Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics of a vulnerability, and produce a numerical score reflecting its severity, as well as a textual representation of that score.
+ severity (string) - Snyk severity for this issue. One of: `high`, `medium` or `low`.
+ identifiers (object) - Additional identifiers for this issue (CVE, CWE, etc).
+ patches (array[Patch]) - Patches to fix this issue, by snyk.
+ packageName (string) - The name of the vulnerable package.
+ creationTime (string)
+ publicationTime (string)
+ modificationTime (string)
+ disclosureTime (string)
+ language (string) - The programming language for this package.
+ packageManager `npm` (string)
+ cvssScore (number) - CVSS Score.
+ alternativeIds (object)
+ from (object) - Paths from which the vulnerable package is required in the code base.
+ upgradePath (object)
+ isUpgradeable (boolean) - Will upgrading this package fix the vulnerability?
+ isPatchable (boolean) - Is a patch by snyk available to fix this vulnerability?

## Maven Request Payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `plain`

+ files (object) - The manifest files:
    + target (MavenFile, required) - the main/root manifest file, encoded according the the "encoding" field.

    + additional (array[MavenAdditionalFile], optional) - additional manifest files (if needed), encoded according the the "encoding" field.


## npm Request Payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `plain`

+ files (object) - The manifest files:
    + target (object, required) - the `package.json` file, encoded according the the "encoding" field.
        + contents: `{"name":"ms","version":"0.7.0","description":"Tiny ms conversion utility","repository":{"type":"git","url":"git://github.com/guille/ms.js.git"},"main":"./index","devDependencies":{"mocha":"*","expect.js":"*","serve":"*"},"component":{"scripts":{"ms/index.js":"index.js"}}}` (string, required) - the contents of `package.json` as a string.

## rubygems Request Payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `plain`

+ files (object) - The manifest files:
    + target (object, required) - the `Gemfile.lock` file, encoded according the the "encoding" field.
        + contents: `GEM\n remote: http://rubygems.org/\n specs:\n actionpack (4.2.5)\n actionview (= 4.2.5)\n activesupport (= 4.2.5)\n rack (~> 1.6)\n rack-test (~> 0.6.2)\n rails-dom-testing (~> 1.0, >= 1.0.5)\n rails-html-sanitizer (~> 1.0, >= 1.0.2)\n actionview (4.2.5)\n activesupport (= 4.2.5)\n builder (~> 3.1)\n erubis (~> 2.7.0)\n rails-dom-testing (~> 1.0, >= 1.0.5)\n rails-html-sanitizer (~> 1.0, >= 1.0.2)\n activesupport (4.2.5)\n i18n (~> 0.7)\n json (~> 1.7, >= 1.7.7)\n minitest (~> 5.1)\n thread_safe (~> 0.3, >= 0.3.4)\n tzinfo (~> 1.1)\n builder (3.2.2)\n erubis (2.7.0)\n haml (3.1.4)\n httparty (0.8.1)\n multi_json\n multi_xml\n i18n (0.7.0)\n json (1.8.3)\n loofah (2.0.3)\n nokogiri (>= 1.5.9)\n mini_portile2 (2.1.0)\n minitest (5.9.1)\n multi_json (1.12.1)\n multi_xml (0.5.5)\n nokogiri (1.6.8.1)\n mini_portile2 (~> 2.1.0)\n rack (1.6.4)\n rack-protection (1.5.3)\n rack\n rack-test (0.6.3)\n rack (>= 1.0)\n rails-deprecated_sanitizer (1.0.3)\n activesupport (>= 4.2.0.alpha)\n rails-dom-testing (1.0.7)\n activesupport (>= 4.2.0.beta, < 5.0)\n nokogiri (~> 1.6.0)\n rails-deprecated_sanitizer (>= 1.0.1)\n rails-html-sanitizer (1.0.3)\n loofah (~> 2.0)\n sinatra (1.3.2)\n rack (~> 1.3, >= 1.3.6)\n rack-protection (~> 1.2)\n tilt (~> 1.3, >= 1.3.3)\n thread_safe (0.3.5)\n tilt (1.4.1)\n tzinfo (1.2.2)\n thread_safe (~> 0.1)\n \n PLATFORMS\n ruby\n \n DEPENDENCIES\n actionpack\n haml\n httparty\n sinatra\n \n BUNDLED WITH\n 1.13.2` (string, required) - the contents of `Gemfile.lock` as a string.

## Gradle Request Payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `plain`

+ files (object) - The manifest files:
    + target (GradleFile, required) - the manifest file, encoded according the the "encoding" field.

## sbt Request Payload
+ encoding: `base64` (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `plain`


+ files (object) - The manifest files:
    + target (SBTFile, required) - the manifest file, encoded according the the "encoding" field.

## pip Request Payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `plain`

+ files (object) - The manifest files:
    + target (object, required) - the `requirements.txt` file, encoded according the the "encoding" field.
        + contents: `supervisor==3.1\noauth2==1.5.211` (string, required) - the contents of `requirements.txt` as a string, encoded according to `encoding` above.

## SemverObject (object)
+ vulnerable (string) - The (semver) range of versions vulnerable to this issue.
+ unaffected (string) - The (semver) range of versions NOT vulnerable to this issue. *Deprecated* and should not be used.

## Patch (object)
+ urls (array[string]) - Links to patch files to fix an issue.
+ version (string) - Versions this patch is applicable to, in semver format.
+ modificationTime (string)
+ comments (array[string])
+ id (string)

## MavenFile (object)
+ contents: `<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd"> <modelVersion>4.0.0</modelVersion> <parent> <artifactId>io.snyk.example</artifactId> <groupId>parent</groupId> <version>1.0-SNAPSHOT</version> </parent> <artifactId>my-project</artifactId> <dependencies> <dependency> <groupId>axis</groupId> <artifactId>axis</artifactId> <version>1.4</version> </dependency> </dependencies> </project>\n` (string, required) - The contents of the file, encoded according to the `encoding` field.

## MavenAdditionalFile (object)
+ contents: `<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd"> <modelVersion>4.0.0</modelVersion> <artifactId>io.snyk.example</artifactId> <groupId>parent</groupId> <version>1.0-SNAPSHOT</version> <dependencies> <dependency> <groupId>org.apache.zookeeper</groupId> <artifactId>zookeeper</artifactId> <version>3.5</version> </dependency> <dependency> <groupId>org.aspectj</groupId> <artifactId>aspectjweaver</artifactId> <version>1.8.2</version> </dependency> </dependencies> </project>\n` (string, required) - The contents of the file, encoded according to the `encoding` field.

## GradleFile (object)
+ contents: `dependencies { compile 'axis:axis:1.4' }` (string, required) - The contents of the file, encoded according to the `encoding` field.

## SBTFile (object)
+ contents: `Cm5hbWUgOj0gInN1YnNlYXJjaCIKCmFzc2VtYmx5SmFyTmFtZSBpbiBhc3NlbWJseSA6PSBzInN1YnNlYXJjaC0wLjIuMC5qYXIiCgpzY2FsYVZlcnNpb24gOj0gIjIuMTEuOCIKCnNjYWxhY09wdGlvbnMgKys9IFNlcSgiLXVuY2hlY2tlZCIsICItZGVwcmVjYXRpb24iKQoKcmVzb2x2ZXJzICs9IFJlc29sdmVyLnNvbmF0eXBlUmVwbygicHVibGljIikKCmxpYnJhcnlEZXBlbmRlbmNpZXMgKz0gIm9yZy5zY2FsYXRlc3QiICUgInNjYWxhdGVzdF8yLjExIiAlICIyLjIuMSIgJSAidGVzdCIKbGlicmFyeURlcGVuZGVuY2llcyArPSAib3JnLnNjYWxhbW9jayIgJSUgInNjYWxhbW9jay1zY2FsYXRlc3Qtc3VwcG9ydCIgJSAiMy4yLjIiICUgInRlc3QiCmxpYnJhcnlEZXBlbmRlbmNpZXMgKz0gIm5ldC5kYXRhYmluZGVyLmRpc3BhdGNoIiAlJSAiZGlzcGF0Y2gtY29yZSIgJSAiMC4xMS4yIgpsaWJyYXJ5RGVwZW5kZW5jaWVzICs9ICJvcmcuc2xmNGoiICUgInNsZjRqLXNpbXBsZSIgJSAiMS42LjYiCmxpYnJhcnlEZXBlbmRlbmNpZXMgKz0gImNvbS5naXRodWIuc2NvcHQiICUlICJzY29wdCIgJSAiMy40LjAiCmxpYnJhcnlEZXBlbmRlbmNpZXMgKz0gInBsLnByb2plY3QxMy5zY2FsYSIgJSUgInJhaW5ib3ciICUgIjAuMiIKbGlicmFyeURlcGVuZGVuY2llcyArPSAiZG5zamF2YSIgJSAiZG5zamF2YSIgJSAiMi4xLjciCmxpYnJhcnlEZXBlbmRlbmNpZXMgKz0gImNvbS50eXBlc2FmZS5ha2thIiAlJSAiYWtrYS1hY3RvciIgJSAiMi40LjEiCmxpYnJhcnlEZXBlbmRlbmNpZXMgKz0gIm9yZy5zY2FsYS1sYW5nLm1vZHVsZXMiICUgInNjYWxhLWpsaW5lIiAlICIyLjEyLjEiCmxpYnJhcnlEZXBlbmRlbmNpZXMgKz0gIm5ldC5ydWlwcGVpeG90b2ciICUlICJzY2FsYS1zY3JhcGVyIiAlICIxLjAuMCIK` (string, required) - The contents of the file, encoded according to the `encoding` field.
# Group Reporting API

The reporting API powers our reports section.

With it you can find answers to questions like how many issues your organisation has, or how many tests have been conducted in a given time frame.

## Latest Issues [/reporting/issues/latest{?page,perPage,sortBy,order}]

Returns issues currently in existence. This data is updated every 30 minutes.

+ Parameters
    + page: `1` (number, optional) - The page of results to request
    + perPage: `100` (number, optional) - The number of results to return per page
    + sortBy: `issueTitle` (enum[string], optional) - The key to sort results by
        + Members
            + `severity` - Sort by the severity of the issue (in the order low, medium, high)
            + `issueTitle` - Sort alphabetically by the issue title
            + `projectName` - Sort alphabetically by the project name
            + `isFixed` - Sort by whether the issue has been fixed
            + `isPatched` - Sort by whether the issue has been patched
            + `isIgnored` - Sort by whether the issue has been ignored
            + `introducedDate` - Sort chronologically by the date that the issue was introduced into the project
            + `isUpgradable` - Sort by whether the issue can be fixed by upgrading to a later version of the dependency
            + `isPatchable` - Sort by whether the issue can be patched
    + order: `asc` (string, optional) - The direction to sort results.

### Get list of latest issues [POST]

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Issues Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Issues)

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "types": ["unsupported-type"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.types is an invalid type unsupported-type"
                    ]
                }
            }

## Issues [/reporting/issues/{?from,to,page,perPage,sortBy,order}]

Returns issues that are present within a time frame. This data is updated every 30 minutes.

+ Parameters
    + from: `2017-07-01` (string) - The date you wish to fetch results from, in the format `YYYY-MM-DD`
    + to: `2017-07-07` (string) - The date you wish to fetch results until, in the format `YYYY-MM-DD`
    + page: `1` (number, optional) - The page of results to request
    + perPage: `100` (number, optional) - The number of results to return per page
    + sortBy: `issueTitle` (enum[string], optional) - The key to sort results by
        + Members
            + `severity` - Sort by the severity of the issue (in the order low, medium, high)
            + `issueTitle` - Sort alphabetically by the issue title
            + `projectName` - Sort alphabetically by the project name
            + `isFixed` - Sort by whether the issue has been fixed
            + `isPatched` - Sort by whether the issue has been patched
            + `isIgnored` - Sort by whether the issue has been ignored
            + `introducedDate` - Sort chronologically by the date that the issue was introduced into the project
            + `isUpgradable` - Sort by whether the issue can be fixed by upgrading to a later version of the dependency
            + `isPatchable` - Sort by whether the issue can be patched
    + order: `asc` (string, optional) - The direction to sort results.

### Get list of issues [POST]

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Issues Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Issues)

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "types": ["unsupported-type"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.types is an invalid type unsupported-type"
                    ]
                }
            }

## Latest issue counts [/reporting/counts/issues/latest{?groupBy}]

Returns the number of issues currently in existence. This data is updated every 30 minutes.

+ Parameters
    + groupBy: `severity` (enum[string], optional) - The field to group results by
        + Members
            + `severity`
            + `fixable`
            + `project,[severity|fixable]`

### Get latest issue counts [POST]

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Issue Counts Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Issue Counts)

    + Body

            {
                "results": [
                    {
                        "day": "2017-07-01",
                        "count": 0,
                        "severity": {
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        },
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "types": ["unsupported-type"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.types is an invalid type unsupported-type"
                    ]
                }
            }

## Issue counts over time [/reporting/counts/issues{?from,to,groupBy}]

Returns issue counts within a time frame. This data is updated every 30 minutes.

+ Parameters
    + from: `2017-07-01` (string) - The date you wish to fetch results from, in the format `YYYY-MM-DD`
    + to: `2017-07-03` (string) - The date you wish to fetch results until, in the format `YYYY-MM-DD`
    + groupBy: `severity` (enum[string], optional) - The field to group results by
        + Members
            + `severity`
            + `fixable`
            + `project,[severity|fixable]`

### Get issue counts [POST]

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Issue Counts Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Issue Counts)

    + Body

            {
                "results": [
                    {
                        "day": "2017-07-01",
                        "count": 0,
                        "severity": {
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        }
                    },
                    {
                        "day": "2017-07-02",
                        "count": 0,
                        "severity": {
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        }
                    },
                    {
                        "day": "2017-07-03",
                        "count": 0,
                        "severity": {
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        }
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "types": ["unsupported-type"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.types is an invalid type unsupported-type"
                    ]
                }
            }

## Latest project counts [/reporting/counts/projects/latest]

Returns the number of projects currently in existence. This data is updated every 30 minutes.

+ Parameters

### Get latest project counts [POST]

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Project Counts Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Project Counts)

    + Body

            {
                "results": [
                    {
                        "day": "2017-07-01",
                        "count": 0
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "projects": ["unsupported-project"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.projects is an invalid project unsupported-project"
                    ]
                }
            }

## Project counts over time [/reporting/counts/projects{?from,to}]

Returns project counts within a time frame. This data is updated every 30 minutes.

+ Parameters
    + from: `2017-07-01` (string) - The date you wish to fetch results from, in the format `YYYY-MM-DD`
    + to: `2017-07-03` (string) - The date you wish to fetch results until, in the format `YYYY-MM-DD`

### Get project counts [POST]

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Project Counts Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Project Counts)

    + Body

            {
                "results": [
                    {
                        "day": "2017-07-01",
                        "count": 0
                    },
                    {
                        "day": "2017-07-02",
                        "count": 0
                    },
                    {
                        "day": "2017-07-03",
                        "count": 0
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "projects": ["unsupported-project"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.projects is an invalid project unsupported-project"
                    ]
                }
            }

## Test counts [/reporting/counts/tests{?from,to,groupBy}]

Returns the number of tests conducted within a time frame. This data is updated in real time.

+ Parameters
    + from: `2017-07-01` (string) - The date you wish to count tests from, in the format `YYYY-MM-DD`
    + to: `2017-07-03` (string) - The date you wish to count tests until, in the format `YYYY-MM-DD`
    + groupBy: `isPrivate` (enum[string], optional) - The field to group results by
        + Members
            + `isPrivate`
            + `issuesPrevented`

### Get test counts [POST]

+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Tests Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Test Counts)

    + Body

            {
                "results": [
                    {
                        "count": 0,
                        "isPrivate": {
                            "true": 0,
                            "false": 0
                        }
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "isPrivate": "non-boolean-value"
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.isPrivate is not a Boolean"
                    ]
                }
            }

# Data Structures

## Issues Filters (object)

+ filters (object)
    + orgs (array, required) - The list of org IDs to filter the results by
    + severity (array) - The severity levels of issues to filter the results by
        + high (string) - Include issues which are high severity
        + medium (string) - Include issues which are medium severity
        + low (string) - Include issues which are low severity
    + types (array) - The type of issues to filter the results by
        + vuln (string) - Include issues which are vulnerabilities
        + license (string) - Include issues which are licenses
    + languages (array) - The type of languages to filter the results by
        + node (string) - Include issues which are for NodeJS projects (npm or yarn package managers)
        + ruby (string) - Include issues which are for Ruby projects (rubygems package manager)
        + java (string) - Include issues which are for Java projects (maven or gradle)
        + scala (string) - Include issues which are for Scala projects (sbt)
        + python (string) - Include issues which are for Python projects (pip)
        + golang (string) - Include issues which are for Golang projects (golang, golangdep or govendor)
        + php (string) - Include issues which are for PHP projects (composer)
        + dotnet (string) - Include issues which are for .Net projects (nuget)
    + projects (array) - The list of project IDs to filter issues by
    + issues (array) - The list of issue IDs to filter issues by
    + ignored (boolean) - If set to `true`, only include issues which are ignored, if set to `false`, only include issues which are not ignored
    + patched (boolean) - If set to `true`, only include issues which are patched, if set to `false`, only include issues which are not patched
    + fixable (boolean) - If set to `true`, only include issues which are fixable, if set to `false`, only include issues which are not fixable
    + isFixed (boolean) - If set to `true`, only include issues which are fixed, if set to `false`, only include issues which are not fixed
    + isUpgradable (boolean) - If set to `true`, only include issues which are upgradable, if set to `false`, only include issues which are not upgradable
    + isPatchable (boolean) - If set to `true`, only include issues which are patchable, if set to `false`, only include issues which are not patchable

## Issue Counts Filters (object)

+ filters (object)
    + orgs (array, required) - The list of org IDs to filter the results by
    + severity (array) - The severity levels of issues to filter the results by
        + high (string) - Include issues which are high severity
        + medium (string) - Include issues which are medium severity
        + low (string) - Include issues which are low severity
    + types (array) - The type of issues to filter the results by
        + vuln (string) - Include issues which are vulnerabilities
        + license (string) - Include issues which are licenses
    + languages (array) - The type of languages to filter the results by
        + node (string) - Include issues which are for NodeJS projects (npm or yarn package managers)
        + ruby (string) - Include issues which are for Ruby projects (rubygems package manager)
        + java (string) - Include issues which are for Java projects (maven or gradle)
        + scala (string) - Include issues which are for Scala projects (sbt)
        + python (string) - Include issues which are for Python projects (pip)
        + golang (string) - Include issues which are for Golang projects (golang, golangdep or govendor)
        + php (string) - Include issues which are for PHP projects (composer)
        + dotnet (string) - Include issues which are for .Net projects (nuget)
    + projects (array) - The list of project IDs to filter issues by
    + ignored (boolean) - If set to `true`, only include issues which are ignored, if set to `false`, only include issues which are not ignored
    + patched (boolean) - If set to `true`, only include issues which are patched, if set to `false`, only include issues which are not patched
    + fixable (boolean) - If set to `true`, only include issues which are fixable, if set to `false`, only include issues which are not fixable

## Project Counts Filters (object)

+ filters (object)
    + orgs (array, required) - The list of org IDs to filter the results by
    + languages (array) - The type of languages to filter the results by
        + node (string) - Include NodeJS projects (npm or yarn package managers)
        + ruby (string) - Include Ruby projects (rubygems package manager)
        + java (string) - Include Java projects (maven or gradle)
        + scala (string) - Include issues which are for Scala projects (sbt)
        + python (string) - Include issues which are for Python projects (pip)
        + golang (string) - Include issues which are for Golang projects (golang, golangdep or govendor)
        + php (string) - Include issues which are for PHP projects (composer)
        + dotnet (string) - Include issues which are for .Net projects (nuget)
    + projects (array) - The list of project IDs to filter the results by

## Tests Filters (object)

+ filters (object)
    + orgs (array, required) - The list of org IDs to filter the results by
    + isPrivate (boolean) - If set to `true`, only include tests which were conducted against private projects, if set to `false` only include tests which were conducted against public projects
    + issuesPrevented (boolean) - If set to `true`, only include tests which prevented issues from being introduced, if set to `false` only include tests which did not prevent issues from being introduced
    + projects (array) - The list of project IDs to filter issues by

## Issues (object)

+ results (array, fixed-type, required) - A list of issues
    + (object, required)
        + issue (object, required)
            + url (string, required) - URL to a page containing information about the issue
            + id (string, required) - The identifier of the issue
            + title (string, required) - The issue title
            + type (string, required) - The issue type, can be "vuln", "license"
            + package (string, required) - The name of the package that the issue relates to
            + version (string, required) - The version of the package that the issue relates to
            + severity (string, required) - The severity status of the issue
            + isUpgradable (boolean) - Whether the issue can be fixed by upgrading to a later version of the dependency
            + isPatchable (boolean) - Whether the issue can be patched
            + jiraIssueUrl (string) - The link to the Jira issue attached to the vulnerability
            + publicationTime (string) - The date that the vulnerability was first published by Snyk (not applicable to licenses)
            + disclosureTime (string) - The date that the vulnerability was first disclosed (not applicable to licenses)
            + language (string) - The language of the issue
            + packageManager (string) - The package manager of the issue
            + identifiers (object) - External identifiers assigned to the issue (not applicable to licenses)
                + CVE (array[string]) - Common Vulnerability Enumeration identifiers
                + CWE (array[string]) - Common Weakness Enumeration identifiers
                + OSVDB (array[string]) - Identifiers assigned by the Open Source Vulnerability Database (OSVDB)
            + credit (array[string]) - The list of people responsible for first uncovering or reporting the issue (not applicable to licenses)
            + CVSSv3 (string) - The CVSS v3 string that signifies how the CVSS score was calculated (not applicable to licenses)
            + cvssScore (string) - The CVSS score that results from running the CVSSv3 string (not applicable to licenses)
            + patches (array) - A list of patches available for the given issue (not applicable to licenses)
                + (object)
                    + id (string) - The identifier of the patch
                    + urls (array[string]) - The URLs where the patch files can be downloaded
                    + version (string) - The version number(s) that the patch can be applied to
                    + comments (array[string]) - Any comments about the patch
                    + modificationTime (string) - When the patch was last modified
            + isIgnored (boolean, required) - Whether the issue has been ignored
            + isPatched (boolean, required) - Whether the issue has been patched (not applicable to licenses)
            + semver (object) - The ranges that are vulnerable and unaffected by the issue
                + vulnerable (string) - The ranges that are vulnerable to the issue
                + unaffected (string) - The ranges that are unaffected by the issue
            + ignored (array) - The list of ignore rules that were applied to the issue (only present if issue was ignored)
                + (object)
                    + reason (string) - A reason why the issue was ignored
                    + expires (string) - The date when the ignore will no longer apply
                    + source (enum[string]) - The place where the ignore rule was applied from
                        + Members
                            + `cli` - The ignore was applied via the CLI or filesystem
                            + `api` - The ignore was applied via the API or website
        + project (object, required)
            + url (string, required) - URL to a page containing information about the project
            + id (string, required) - The identifier of the project
            + name (string, required) - The name of the project
            + source (string, required) - The source of the project (e.g. github, heroku etc)
            + packageManager (string, required) - The package manager for the project (e.g. npm, rubygems etc)
            + targetFile (string) - The file path to the dependency manifest or lock file (e.g. package.json, Gemfile.lock etc)
        + isFixed (boolean, required) - Whether the issue has been fixed
        + introducedDate (string, required) - The date that the issue was introduced into the project
        + patchedDate (string) - The date that the issue was patched
        + fixedDate (string) - The date that the issue was fixed
+ total (number, required) - The total number of results found

## Issue Counts (object)

+ results (array, fixed-type, required) - A list of issue counts by day
    + (object, required)
        + day (string, required) - The date in the format `YYYY-MM-DD`
        + count (number, required) - The number of issues
        + severity (object)
            + high (number) - The number of high severity issues
            + medium (number) - The number of medium severity issues
            + low (number) - The number of low severity issues
        + fixable (object)
            + true (number) - The number of fixable issues
            + false (number) - The number of non-fixable issues

## Project Counts (object)

+ results (array, fixed-type, required) - A list of project counts by day
    + (object, required)
        + day (string, required) - The date in the format `YYYY-MM-DD`
        + count (number, required) - The number of projects

## Test Counts (object)

+ results (array, fixed-type, required) - A list of test counts
    + (object, required)
        + count (number, required) - The number of tests conducted
        + isPrivate (object)
            + true (number) - The number of tests conducted against private projects
            + false (number) - The number of tests conducted against public projects
        + issuesPrevented (object)
            + true (number) - The number of tests that prevented issues from being introduced
            + false (number) - The number of tests that did not prevent issues from being introduced

## Error Response (object)

+ code: 400 (number, required) - The error response code
+ ok (boolean, required)
+ error (object, required)
    + name (string, required) - A descriptive message of the error
    + innerErrors (array[string]) - A list of additional reasons why the error occurred
# Data Structures

## Notification Settings Request (object)
+ `new-issues-remediations` (Notification Setting Request)
+ `project-imported` (Notification Setting Request)
+ `test-limit` (Notification Setting Request)
+ `weekly-report` (Notification Setting Request)

## Notification Settings Response (object)
+ `new-issues-remediations` (Notification Setting Response)
+ `project-imported` (Notification Setting Response)
+ `test-limit` (Notification Setting Response)
+ `weekly-report` (Notification Setting Response)

## Notification Setting Request (object)
+ enabled: true (boolean, required) - Whether notifications should be sent
+ issueSeverity (enum[string]) - The severity levels of issues to send notifications for (only applicable for `new-remediations-vulnerabilities` notificationType)
    + Members
        + all (string) - Include all issues
        + high (string) - Include issues which are high severity
    + Sample: high
+ issueType (enum[string]) - Filter the types of issue to include in notifications (only applicable for `new-remediations-vulnerabilities` notificationType)
    + Members
        + all (string) - Include vulnerability & license issues
        + vuln (string) - Include vulnerability issues
        + license (string) - Include license issues
    + Sample: vuln


## Notification Setting Response (Notification Setting Request)
+ inherited (boolean) - Whether the setting was found on the requested context directly or inherited from a parent

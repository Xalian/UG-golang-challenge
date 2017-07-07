# UG-golang-challenge

## Requirements
1. Respond to HTTP requests with a list of vulnerabilities in JSON format.
   The initial list of vulnerabilities are in the provided data file, and they must be filtered based on the parameters specified in the HTTP request (see below).  
 
2. Accept a “severity_at_least” parameter to filter out vulnerabilities with a severity of less than the provided parameter.
 
3. Accept a “since” parameter to filter out vulnerabilities which were reported prior to the date indicated by the provided parameter.
 
4. Accept a “limit” parameter which will limit the number of vulnerabilities in the response to the provided amount.
 
5. Handle any erroneous/strange input appropriately.

Your code should be hosted on github and include any appropriate documentation and tests. 

## Command-line Flags
The program has two flags `port` and `file`.

`port` is the port number that the program listens to, the default is `:8080`.

`file` is the location of the .json file that contains the vulnerabilities, the default is `data/data.json`.

## Usage
The program will return the full list of correctly input vulnerabilities when no supported parameters are passed to the program.  
The vulnerabilities are always sorted in the same manner that they are given to the program.

### Severity filtering
This parameter will filter out all vulnerabilities that have a severity rating below the given number.  
The URL should contain the parameter "severity_at_least", followed by a number.
An example of a properly formatted Severity param is:  
`/?severity_at_least=4`

### Date filtering
This parameter will filter out all vulnerabilities that happened prior to the given date.  
The URL should contain the parameter "since", followed by a date in the format `YYYY-MM-DD`.
An example of a properly formatted Date param is:  
`/?since=2016-12-23`

### Limited number
This parameter will limit the amount of vulnerabilities given to the given number or the amount of vulnerabilities, whichever is lower.  
The URL should contain the parameter "limit", followed by a number.
An example of a properly formatted Limit param is:  
`/?limit=17`

### Combining Parameters
Parameters can be combined in the same url by placing `&` in between each parameter, the ordering does not matter.  
A properly formatted query involving all three parameters is:  
`/?limit=17&since=2016-12-23&severity_at_least=4`

## Erroneous Input

## Parameters
Any unsupported parameters provided to the program are ignored and any supported parameters with incorrect input are also ignored.
## .json
Any ill-formatted .json is filtered out of the program.

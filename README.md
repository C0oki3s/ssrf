## ssrf

[![NPM Version][ssrf-badgen]][download-url]
![LICENSE](https://badgen.net/badge/license/MIT/blue)

## Server-Side Request Forgery (SSRF)
the attacker can abuse functionality on the server to read or update internal resources. The attacker can supply or modify a URL which the code running on the server will read or submit data to, and by carefully selecting the URLs, the attacker may be able to read server configuration such as AWS metadata, connect to internal services like http enabled databases or perform post requests towards internal services which are not intended to be exposed [read more](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)

## Install
`npm install ssrf`

## Usage

```js

ssrf.options({
  blacklist:"/ssrf/list.txt", //Linux if windows pass 'C:\\Users\\host.txt'
  path:false
})
let DNS_rebinding = "https://c0okie.xyz/attacker.html" //my domain running on 127.0.0.1
let url = "http://evil.com" //Blacklist host
let ip = "http://13.54.97.2" //Blacklist IP

//Normal request
const fetch = async() =>{
  try {
    const gotssrf = await ssrf.url(ip) //return host or ip 
    axios.get(gotssrf)
    .then((data) => console.log(data.data))
    .catch(err => console.log(err))
  } catch (error) {
    console.log("Handle Error for Front End User")
  }
}
fetch()
``` 

## ssrf.url()

ssrf.url return Promise so use await ssrf.url("http://example.com") in try-catch block
     
```js
     
try{
        const result = await ssrf.url(url)
        //do stuff if success
}catch{
        //do stuff if fail
} 
```

### ssrf.options({})

options takes two argument 
  + blacklist 
  + path

#### blacklist

Blacklist parameter takes input of absolute path to a text file 
 Ex:- /usr/list/blacklist.txt (Linux)
 C:\\Users\\host.txt (windows)
 By default it don't have any blacklist but if an user passes absolute path then it reads file and run a for loop everytime it hits middleware
        
   
##### File format 

```
evil.com
example.com
87.26.7.9
98.72.6.2
```
                
      
#### path

Path parameter taker A Boolean value as (true or false)
Where by default its True which means it will return /path and ?parameters attached to Host 

`Ex:- if a user send's http://example.com/path1?param=1 return http://example.com/path1?param=1`
          
    
##### True

return absolute Url `http://example.com/path1?param=1`
      
##### False

return  Hostname `http://example.com or http://www.example.com`

This module Prevents From reserverd character `@` attack and DNS rebinding attack. to Learn more about DNS rebinding [more](https://github.com/C0oki3s/Payloads/tree/main/DNS-Rebinding)
           
          

[download-url]: https://www.npmjs.com/package/ssrf
[ssrf-badgen]: https://badgen.net/npm/v/ssrf

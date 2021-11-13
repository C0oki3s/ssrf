const ssrf = require("../lib/index")
const axios = require("axios").default

ssrf.options({
  blacklist:"/lists/ssrf/host.txt", //window's
  path:false
})
let DNS_rebinding = "https://c0okie.xyz/attacker.html" //my domain running on 127.0.0.1
let url = "http://evil.com" //Blacklist host
let ip = "http://13.54.97.2" //Blacklist IP

//Normal request
const fetch = async() =>{
  try {
    const gotssrf = await ssrf.url(ip)
    axios.get(gotssrf)
    .then((data) => console.log(data.data))
    .catch(err => console.log(err))
  } catch (error) {
    console.log("Handle Error for Front End User")
  }
}
fetch()
 



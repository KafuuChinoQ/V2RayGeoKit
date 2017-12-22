没有说明（

    npm i && npm run start

example rules
```
"rules": [{
    "type": "field",
    "ip": ["geoip:proxy"],
    "outboundTag": "proxy"
  }, {
    "type": "field",
    "domain": ["geosite:proxy"],
    "outboundTag": "proxy"
  }, {
    "type": "field",
    "ip": ["geoip:reject"],
    "outboundTag": "reject"
  }, {
    "type": "field",
    "domain": ["geosite:reject"],
    "outboundTag": "reject"
  }, {
    "type": "field",
    "ip": ["geoip:direct"],
    "outboundTag": "direct"
  }, {
    "type": "field",
    "domain": ["geosite:direct"],
    "outboundTag": "direct"
  }, {
    "type": "field",
    "ip": ["geoip:cn"],
    "outboundTag": "direct"
  }]
```

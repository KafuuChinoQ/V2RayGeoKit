没有说明（

    npm i && npm run start

example rules
```
"rules": [{
      "type": "field",
      "ip": [
        "geoip:custom:reject",
        "geoip:surge:reject"
      ],
      "outboundTag": "reject"
    },
    {
      "type": "field",
      "domain": [
        "geosite:custom:reject",
        "geosite:surge:reject"
      ],
      "outboundTag": "reject"
    },
    {
      "type": "field",
      "ip": [
        "geoip:custom:direct",
        "geoip:surge:direct",
        "geoip:private"
      ],
      "outboundTag": "direct"
    },
    {
      "type": "field",
      "domain": [
        "geosite:custom:direct",
        "geosite:surge:direct",
        "geosite:gfwlist:direct",
        "geosite:cn"
      ],
      "outboundTag": "direct"
    },
    {
      "type": "field",
      "ip": [
        "geoip:custom:proxy",
        "geoip:surge:proxy"
      ],
      "outboundTag": "proxy"
    },
    {
      "type": "field",
      "domain": [
        "geosite:custom:proxy",
        "geosite:surge:proxy",
        "geosite:gfwlist:proxy"
      ],
      "outboundTag": "proxy"
    }
  ]
```

'use strict';

const protobuf = require("protobufjs");
const fs = require('fs');
const request = require('request-promise');
const neatCsv = require('neat-csv');
const IP = require('ip');
const isCidr = require('is-cidr');
const dedupe = require('dedupe');

const rule_urls = [
    'https://github.com/lhie1/Surge/raw/master/Basics.conf',
    'https://github.com/lhie1/Surge/raw/master/DIRECT.conf',
    'https://github.com/lhie1/Surge/raw/master/PROXY.conf',
    'https://github.com/lhie1/Surge/raw/master/REJECT.conf'
];

const gfwlist_url = 'https://github.com/gfwlist/gfwlist/raw/master/gfwlist.txt';

function getType(type_str) {
    type_str = type_str.toLowerCase();
    if (type_str.includes('reject')) {
        return 'reject'
    } else if (type_str.includes('proxy')) {
        return 'proxy'
    } else if (type_str.includes('direct') || type_str.includes('domestic') || type_str.includes('other') || type_str.includes('🍎')) {
        return 'direct'
    } else {
        return 'direct'
    }
}

function parseRulesFromUrl(url) {
    let domains = {reject: [], direct: [], proxy: []}, keywords = {reject: [], direct: [], proxy: []},
        ipcidrs = {reject: [], direct: [], proxy: []};
    return request(url).then(body => {
        let lines = body.split('\n');
        lines.map(line => {
            if (!!line) {
                if (line.toUpperCase().startsWith('DOMAIN')) {
                    line = line.split(',');
                    let opt = line[0], domain = line[1], type = line[2];
                    if (opt.endsWith('KEYWORD')) {
                        keywords[getType(type)].push(domain)
                    } else {
                        domains[getType(type)].push(domain)
                    }
                } else if (line.toUpperCase().startsWith('IP-CIDR')) {
                    line = line.split(',');
                    let ip = line[1], type = line[2];
                    ipcidrs[getType(type)].push(parseIP(ip))
                }
            }
        });
        return {domains, keywords, ipcidrs}
    })
}

function getDomain(url) {
    url = url.replace(/https?:\/\//g, '');
    url = url.replace(/\./g, '\\.');
    url = url.replace('*', '.*');
    let i = url.indexOf('/');
    if (i > 1) {
        url = url.substr(0, i);
    }
    return url;
}

function parseGFWListRules() {
    let domains = {direct: [], proxy: []};
    return request(gfwlist_url).then(body => {
        body = new Buffer(body, 'base64').toString();
        let lines = body.split('\n');
        let supplemental = false;
        lines.map(line => {
            if (!!line) {
                if (!(line.startsWith('!') || line.startsWith('['))) {
                    if (line.startsWith('||')) {
                        line = getDomain(line.substr(2));
                        if (!!line && !domains.proxy.includes(line)) {
                            domains.proxy.push(line)
                        }
                    } else if (line.startsWith('|')) {
                        line = getDomain(line.substr(1));
                        if (!!line && !domains.proxy.includes(line)) {
                            domains.proxy.push(line)
                        }
                    } else if (line.startsWith('@@')) {
                        line = getDomain(line.substr(2).replace(/\|{1,2}/, ''));
                        if (!!line && !domains.direct.includes(line)) {
                            domains.direct.push(line)
                        }
                    } else {
                        if (!line.startsWith('/') && !supplemental) {
                            line = getDomain(line);
                            if (!!line && !domains.proxy.includes(line)) {
                                domains.proxy.push(line)
                            }
                        }
                    }
                } else if (line.includes('Supplemental List Start')) {
                    supplemental = true;
                } else if (supplemental && line.includes('Supplemental List End')) {
                    supplemental = false;
                }
            }
        });
        domains.proxy.sort((a, b) => a.localeCompare(b));
        domains.direct.sort((a, b) => a.localeCompare(b));
        return {domains}
    })
}

function parseIP(ip) {
    ip = ip.split('/');
    let addr = ip[0], mask = ip[1];
    return {
        ip: IP.toBuffer(addr),
        prefix: parseInt(mask)
    }
}

async function parseGeoLite() {
    let country_codes = {};
    let cidrs = [];
    let country_csv = fs.readFileSync('./geolite/GeoLite2-Country-Locations-en.csv');
    await neatCsv(country_csv).then(rows => {
        rows.map(row => {
            country_codes[row.geoname_id] = row.country_iso_code.toUpperCase()
        })
    });

    let ipv4_csv = fs.readFileSync('./geolite/GeoLite2-Country-Blocks-IPv4.csv');
    await neatCsv(ipv4_csv).then(rows => {
        rows.map(row => {
            if (!!country_codes[row.geoname_id]) {
                let country_code = country_codes[row.geoname_id];
                let cidr = parseIP(row.network);
                if (cidrs.filter(cidr => cidr.countryCode === country_code).length > 0) {
                    cidrs.find(cidr => cidr.countryCode === country_code).cidr.push(cidr)
                } else {
                    cidrs.push({
                        countryCode: country_code,
                        cidr: [cidr]
                    })
                }
            }
        })
    });

    let ipv6_csv = fs.readFileSync('./geolite/GeoLite2-Country-Blocks-IPv6.csv');
    await neatCsv(ipv6_csv).then(rows => {
        rows.map(row => {
            if (!!country_codes[row.geoname_id]) {
                let country_code = country_codes[row.geoname_id];
                let cidr = parseIP(row.network);
                if (cidrs.filter(cidr => cidr.countryCode === country_code).length > 0) {
                    cidrs.find(cidr => cidr.countryCode === country_code).cidr.push(cidr)
                } else {
                    cidrs.push({
                        countryCode: country_code,
                        cidr: [cidr]
                    })
                }
            }
        })
    });

    cidrs.sort((a, b) => a.countryCode.localeCompare(b.countryCode));
    return cidrs;
}

function loadCustomRules(filename) {
    let domains = [], ipcidrs = [];
    let lines = fs.readFileSync(filename).toString();
    lines = lines.split('\n');
    lines.map(line => {
        if (!!line) {
            line = line.replace('\r', '');
            if (!line.startsWith('#')) {
                if (isCidr(line)) {
                    ipcidrs.push(parseIP(line))
                } else {
                    domains.push(line)
                }
            }
        }
    });
    return {domains, ipcidrs}
}

async function main() {
    try {
        let proto_root = await protobuf.load("router.proto");
        let GeoSiteList = proto_root.lookupType("router.GeoSiteList");
        let GeoIPList = proto_root.lookupType("router.GeoIPList");

        let sites_proxy = [], sites_direct = [], sites_reject = [], ips_proxy = [], ips_direct = [], ips_reject = [];

        // load custom rules
        console.log('loading custom rules..');
        let proxy_custom_rules = loadCustomRules('./custom/proxy.txt');
        sites_proxy.push(...proxy_custom_rules.domains.map(domain => Object({type: 1, value: domain})));
        ips_proxy.push(...proxy_custom_rules.ipcidrs);
        let direct_custom_rules = loadCustomRules('./custom/direct.txt');
        sites_direct.push(...direct_custom_rules.domains.map(domain => Object({type: 1, value: domain})));
        ips_direct.push(...direct_custom_rules.ipcidrs);
        let reject_custom_rules = loadCustomRules('./custom/reject.txt');
        sites_reject.push(...reject_custom_rules.domains.map(domain => Object({type: 1, value: domain})));
        ips_reject.push(...reject_custom_rules.ipcidrs);
        // load custom rules

        {
            console.log('loading gfwlist rules..');
            let {domains} = await parseGFWListRules();
            let gfwlist_proxy, gfwlist_direct, gfwlist_reject = [];
            gfwlist_proxy = domains.proxy.map(domain => Object({type: 1, value: domain}));
            gfwlist_direct = domains.direct.map(domain => Object({type: 1, value: domain}));
            gfwlist_proxy.push(...proxy_custom_rules.domains.map(domain => Object({type: 1, value: domain})));
            gfwlist_direct.push(...direct_custom_rules.domains.map(domain => Object({type: 1, value: domain})));
            gfwlist_reject.push(...reject_custom_rules.domains.map(domain => Object({type: 1, value: domain})));
            gfwlist_proxy = dedupe(gfwlist_proxy.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
            gfwlist_direct = dedupe(gfwlist_direct.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
            gfwlist_reject = dedupe(gfwlist_reject.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);

            let site_list = GeoSiteList.create({
                entry: [
                    {
                        countryCode: 'PROXY',
                        domain: gfwlist_proxy
                    }, {
                        countryCode: 'DIRECT',
                        domain: gfwlist_direct
                    }, {
                        countryCode: 'REJECT',
                        domain: gfwlist_reject
                    }
                ]
            });
            let buffer = GeoSiteList.encode(site_list).finish();
            fs.writeFileSync('./gfwlist/geosite.dat', buffer);

            buffer = fs.readFileSync('./gfwlist/geosite.dat');
            site_list = GeoSiteList.decode(buffer);
            console.log('write gfwlist version geosite.dat');
        }
        {
            console.log('loading online rules..');
            for (let url of rule_urls) {
                let {domains, keywords, ipcidrs} = await parseRulesFromUrl(url);
                keywords.proxy.map(keyword => {
                    keyword = `.*?${keyword}.*`;
                    if (sites_proxy.filter(site => site.value === keyword).length === 0) {
                        sites_proxy.push({type: 1, value: keyword})
                    }
                });
                keywords.direct.map(keyword => {
                    keyword = `.*?${keyword}.*`;
                    if (sites_direct.filter(site => site.value === keyword).length === 0) {
                        sites_direct.push({type: 1, value: keyword})
                    }
                });
                keywords.reject.map(keyword => {
                    keyword = `.*?${keyword}.*`;
                    if (sites_reject.filter(site => site.value === keyword).length === 0) {
                        sites_reject.push({type: 1, value: keyword})
                    }
                });
                domains.proxy.map(domain => {
                    if (sites_proxy.filter(site => site.value.replace('\\', '') === domain).length === 0) {
                        sites_proxy.push({type: 2, value: domain})
                    }
                });
                domains.direct.map(domain => {
                    if (sites_direct.filter(site => site.value.replace('\\', '') === domain).length === 0) {
                        sites_direct.push({type: 2, value: domain})
                    }
                });
                domains.reject.map(domain => {
                    if (sites_reject.filter(site => site.value.replace('\\', '') === domain).length === 0) {
                        sites_reject.push({type: 2, value: domain})
                    }
                });
                ipcidrs.proxy.map(ipcidr => {
                    if (ips_proxy.filter(cidr => cidr.ip === ipcidr.ip && cidr.prefix === ipcidr.prefix).length === 0) {
                        ips_proxy.push(ipcidr)
                    }
                });
                ipcidrs.direct.map(ipcidr => {
                    if (ips_direct.filter(cidr => cidr.ip === ipcidr.ip && cidr.prefix === ipcidr.prefix).length === 0) {
                        ips_direct.push(ipcidr)
                    }
                });
                ipcidrs.reject.map(ipcidr => {
                    if (ips_reject.filter(cidr => cidr.ip === ipcidr.ip && cidr.prefix === ipcidr.prefix).length === 0) {
                        ips_reject.push(ipcidr)
                    }
                })
            }
            sites_proxy = dedupe(sites_proxy.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
            sites_direct = dedupe(sites_direct.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
            sites_reject = dedupe(sites_reject.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);

            let site_list = GeoSiteList.create({
                entry: [
                    {
                        countryCode: 'PROXY',
                        domain: sites_proxy
                    }, {
                        countryCode: 'DIRECT',
                        domain: sites_direct
                    }, {
                        countryCode: 'REJECT',
                        domain: sites_reject
                    }
                ]
            });
            let buffer = GeoSiteList.encode(site_list).finish();
            fs.writeFileSync('geosite.dat', buffer);

            buffer = fs.readFileSync('geosite.dat');
            site_list = GeoSiteList.decode(buffer);
            console.log('write geosite.dat');

            console.log('loading geolite ip datas..');
            let geo_ips = await parseGeoLite();
            let ip_list = GeoIPList.create({
                entry: [...geo_ips,
                    {
                        countryCode: 'PROXY',
                        cidr: ips_proxy
                    }, {
                        countryCode: 'DIRECT',
                        cidr: ips_direct
                    }, {
                        countryCode: 'REJECT',
                        cidr: ips_reject
                    }
                ]
            });

            buffer = GeoIPList.encode(ip_list).finish();
            fs.writeFileSync('geoip.dat', buffer);

            buffer = fs.readFileSync('geoip.dat');
            ip_list = GeoIPList.decode(buffer);
            console.log('write geoip.dat');
        }
    } catch (error) {
        console.error(error)
    }
}

main();

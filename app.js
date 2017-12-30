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

function getDomain(url) {
    url = url.replace(/https?:\/\//g, '');
    let i = url.indexOf('/');
    if (i > 1) {
        url = url.substr(0, i);
    }
    return url;
}

function parseIP(ip) {
    ip = ip.split('/');
    let addr = ip[0], mask = ip[1];
    return {
        ip: IP.toBuffer(addr),
        prefix: parseInt(mask)
    }
}

function formatDomain(domain) {
    let {value, type} = domain;
    if (type === 'suffix') {
        if (value.startsWith('.')) {
            type = 1;
            value = value.replace(/\./g, '\\.');
            value = value.replace('*', '.*');
        } else {
            type = 2
        }
    } else if (type === 'full') {
        type = 1;
        value = value.replace(/\./g, '\\.');
        value = value.replace('*', '.*');
        value = '^' + value + '$';
    } else if (type === 'keyword') {
        type = 0;
    } else {
        type = 1;
    }
    return {type, value};
}

function parseRulesFromUrl(url) {
    let domains = {reject: [], direct: [], proxy: []}, ipcidrs = {reject: [], direct: [], proxy: []};
    return request(url).then(body => {
        let lines = body.split('\n');
        lines.map(line => {
            if (!!line) {
                if (line.toUpperCase().startsWith('DOMAIN')) {
                    line = line.split(',');
                    let opt = line[0], domain = line[1], type = line[2];
                    if (opt.endsWith('KEYWORD')) {
                        domains[getType(type)].push({value: domain, type: 'keyword'})
                    } else if (opt.endsWith('SUFFIX')) {
                        domains[getType(type)].push({value: domain, type: 'suffix'})
                    } else {
                        domains[getType(type)].push({value: domain, type: 'full'})
                    }
                } else if (line.toUpperCase().startsWith('IP-CIDR')) {
                    line = line.split(',');
                    let ip = line[1], type = line[2];
                    ipcidrs[getType(type)].push(ip)
                }
            }
        });
        return {domains, ipcidrs}
    })
}

function parseGFWListRules() {
    let direct = [], proxy = [];
    return request(gfwlist_url).then(body => {
        body = new Buffer(body, 'base64').toString();
        let lines = body.split('\n');
        let supplemental = false;
        lines.map(line => {
            if (!!line) {
                if (!(line.startsWith('!') || line.startsWith('['))) {
                    if (line.startsWith('||')) {
                        line = getDomain(line.substr(2));
                        if (!!line && proxy.filter(p => p.value === line).length === 0) {
                            proxy.push({value: line, type: 'suffix'})
                        }
                    } else if (line.startsWith('|')) {
                        line = getDomain(line.substr(1));
                        if (!!line && proxy.filter(p => p.value === line).length === 0) {
                            proxy.push({value: line, type: 'full'})
                        }
                    } else if (line.startsWith('@@')) {
                        line = line.substr(2);
                        let type = 'suffix';
                        if (line[1] !== '|') {
                            type = 'full'
                        }
                        line = getDomain(line.replace(/\|{1,2}/, ''));
                        if (!!line && direct.filter(p => p.value === line).length === 0) {
                            direct.push({value: line, type})
                        }
                    } else {
                        if (!line.startsWith('/') && !supplemental) {
                            line = getDomain(line);
                            if (!!line && proxy.filter(p => p.value === line).length === 0) {
                                proxy.push({value: line, type: 'suffix'})
                            }
                        } else if (line.startsWith('/')) {
                            // regex
                            // console.log(line)
                        }
                    }
                } else if (line.includes('Supplemental List Start')) {
                    supplemental = true;
                } else if (supplemental && line.includes('Supplemental List End')) {
                    supplemental = false;
                }
            }
        });
        proxy.sort((a, b) => a.value.localeCompare(b.value));
        direct.sort((a, b) => a.value.localeCompare(b.value));
        return {proxy, direct}
    })
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
                    ipcidrs.push(line)
                } else {
                    domains.push({value: line, type: 'suffix'})
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

        let sites_proxy = [], sites_direct = [], sites_reject = [], sites_cn = [],
            ips_proxy = [], ips_direct = [], ips_reject = [];

        // load custom rules
        console.log('loading custom rules..');

        let proxy_custom_rules = loadCustomRules('./custom/proxy.txt');
        ips_proxy.push(...proxy_custom_rules.ipcidrs);

        let direct_custom_rules = loadCustomRules('./custom/direct.txt');
        ips_direct.push(...direct_custom_rules.ipcidrs);

        let reject_custom_rules = loadCustomRules('./custom/reject.txt');
        ips_reject.push(...reject_custom_rules.ipcidrs);

        let cn_custom_rules = loadCustomRules('./custom/cn.txt');
        sites_cn = cn_custom_rules.domains.map(domain => formatDomain(domain));
        // load custom rules

        {
            console.log('loading gfwlist ver. rules..');
            let {proxy: gfwlist_proxy, direct: gfwlist_direct} = await parseGFWListRules();
            let gfwlist_reject = [];

            // push custom rules
            gfwlist_proxy.push(...proxy_custom_rules.domains);
            gfwlist_direct.push(...direct_custom_rules.domains);
            gfwlist_reject.push(...reject_custom_rules.domains);

            // deduplicate & sort
            gfwlist_proxy = dedupe(gfwlist_proxy.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
            gfwlist_direct = dedupe(gfwlist_direct.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
            gfwlist_reject = dedupe(gfwlist_reject.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);

            // convert to proto
            gfwlist_proxy = gfwlist_proxy.map(domain => formatDomain(domain));
            gfwlist_direct = gfwlist_direct.map(domain => formatDomain(domain));
            gfwlist_reject = gfwlist_reject.map(domain => formatDomain(domain));

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
                    }, {
                        countryCode: 'CN',
                        domain: sites_cn
                    }
                ]
            });
            let buffer = GeoSiteList.encode(site_list).finish();
            fs.writeFileSync('./gfwlist/geosite.dat', buffer);

            buffer = fs.readFileSync('./gfwlist/geosite.dat');
            site_list = GeoSiteList.decode(buffer);
            console.log('write gfwlist ver. geosite.dat');
        }

        {
            console.log('loading surge ver. rules..');
            for (let url of rule_urls) {
                let {domains, ipcidrs} = await parseRulesFromUrl(url);
                sites_proxy.push(...domains.proxy);
                sites_direct.push(...domains.direct);
                sites_reject.push(...domains.reject);
                ips_proxy.push(...ipcidrs.proxy);
                ips_direct.push(...ipcidrs.direct);
                ips_reject.push(...ipcidrs.reject);
            }

            // push custom rules
            sites_proxy.push(...proxy_custom_rules.domains);
            sites_direct.push(...direct_custom_rules.domains);
            sites_reject.push(...reject_custom_rules.domains);
            ips_proxy.push(...proxy_custom_rules.ipcidrs);
            ips_direct.push(...direct_custom_rules.ipcidrs);
            ips_reject.push(...reject_custom_rules.ipcidrs);

            // deduplicate & sort
            sites_proxy = dedupe(sites_proxy.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
            sites_direct = dedupe(sites_direct.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
            sites_reject = dedupe(sites_reject.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
            ips_proxy = dedupe(ips_proxy.sort((a, b) => a.localeCompare(b)));
            ips_direct = dedupe(ips_direct.sort((a, b) => a.localeCompare(b)));
            ips_reject = dedupe(ips_reject.sort((a, b) => a.localeCompare(b)));

            // convert to proto
            sites_proxy = sites_proxy.map(domain => formatDomain(domain));
            sites_direct = sites_direct.map(domain => formatDomain(domain));
            sites_reject = sites_reject.map(domain => formatDomain(domain));
            ips_proxy = ips_proxy.map(ipcidr => parseIP(ipcidr));
            ips_direct = ips_direct.map(ipcidr => parseIP(ipcidr));
            ips_reject = ips_reject.map(ipcidr => parseIP(ipcidr));

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
                    }, {
                        countryCode: 'CN',
                        domain: sites_cn
                    }
                ]
            });
            let buffer = GeoSiteList.encode(site_list).finish();
            fs.writeFileSync('geosite.dat', buffer);

            buffer = fs.readFileSync('geosite.dat');
            site_list = GeoSiteList.decode(buffer);
            console.log('write surge ver. geosite.dat');

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

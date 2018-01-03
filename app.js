'use strict';

const protobuf = require("protobufjs");
const fs = require('fs');
const request = require('request-promise');
const neatCsv = require('neat-csv');
const IP = require('ip');
const isCidr = require('is-cidr');
const dedupe = require('dedupe');

const rule_urls = fs.readFileSync('./surge_rules.txt').toString().split('\n');

const gfwlist_url = 'https://github.com/gfwlist/gfwlist/raw/master/gfwlist.txt';

const site_rules = {}, ip_rules = {};

function pushSiteRules(country_code, rules) {
    if (rules.length > 0) {
        if (!!site_rules[country_code]) {
            rules.push(...site_rules[country_code]);
            rules = dedupe(rules.sort((a, b) => a.value.localeCompare(b.value)), a => a.value);
        }
        site_rules[country_code] = rules
    }
}

function pushIPRules(country_code, rules) {
    if (rules.length > 0) {
        if (!!ip_rules[country_code]) {
            rules.push(...ip_rules[country_code]);
            rules = dedupe(rules.sort((a, b) => a.localeCompare(b)), a => a);
        }
        ip_rules[country_code] = rules
    }
}

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
    url = decodeURIComponent(url);
    url = url.replace(/https?:\/\//g, '');
    let i = url.indexOf(':') > 1 ? url.indexOf(':') : url.indexOf('/');
    if (i > 1) {
        url = url.substr(0, i);
    }
    if (!url.includes('.')) {
        return null;
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
                        if (!!line) {
                            if (proxy.filter(p => p.value === line).length === 0) {
                                proxy = proxy.filter(p => p.value !== line)
                            }
                            if (direct.filter(p => p.value === line).length === 0) {
                                direct.push({value: line, type})
                            }
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

function loadCustomRules(filename, is_official = false) {
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
                    if (domains.filter(domain => domain.value === line).length === 0) {
                        domains.push({value: line, type: 'suffix'})
                    }
                }
            }
        }
    });
    if (!is_official && domains.length === 0) {
        domains.push({value: '�', type: 'full'})
    }
    domains = domains.sort((a, b) => a.value.localeCompare(b.value));
    if (!is_official && ipcidrs.length === 0) {
        ipcidrs.push('233.333.333.333/33')
    }
    return {domains, ipcidrs}
}

async function main() {
    try {
        let proto_root = await protobuf.load("router.proto");
        let GeoSiteList = proto_root.lookupType("router.GeoSiteList");
        let GeoIPList = proto_root.lookupType("router.GeoIPList");

        // load official rules
        console.log('loading official rules..');
        let official_filenames = fs.readdirSync('./official');
        for (let official_filename of official_filenames) {
            let country_code = official_filename.substr(0, official_filename.indexOf('.'));
            let {domains, ipcidrs} = loadCustomRules('./official/' + official_filename, true);
            pushSiteRules(country_code, domains);
            pushIPRules(country_code, ipcidrs);
        }
        // load official rules

        // load custom rules
        console.log('loading custom rules..');
        let custom_filenames = fs.readdirSync('./custom');
        for (let custom_filename of custom_filenames) {
            let country_code = custom_filename.substr(0, custom_filename.indexOf('.'));
            let {domains, ipcidrs} = loadCustomRules('./custom/' + custom_filename);
            pushSiteRules('custom:' + country_code, domains);
            pushIPRules('custom:' + country_code, ipcidrs);
        }
        // load custom rules

        console.log('loading geolite ip datas..');
        let geo_ips = await parseGeoLite();

        console.log('loading gfwlist rules..');
        let {proxy, direct} = await parseGFWListRules();
        pushSiteRules('gfwlist:proxy', proxy);
        pushSiteRules('gfwlist:direct', direct);

        console.log('loading surge style rules..');
        for (let url of rule_urls) {
            if (!url) continue;
            let {domains, ipcidrs} = await parseRulesFromUrl(url);
            for (let key in domains) {
                if (domains.hasOwnProperty(key)) {
                    pushSiteRules('surge:' + key, domains[key]);
                }
            }
            for (let key in ipcidrs) {
                if (ipcidrs.hasOwnProperty(key)) {
                    pushIPRules('surge:' + key, ipcidrs[key]);
                }
            }
        }

        let site_list = GeoSiteList.create({
            entry: Object.keys(site_rules).map(key => {
                let rules = site_rules[key];
                rules = rules.map(domain => formatDomain(domain));
                return {countryCode: key.toUpperCase(), domain: rules}
            })
        });
        let buffer = GeoSiteList.encode(site_list).finish();
        fs.writeFileSync('./dist/geosite.dat', buffer);

        buffer = fs.readFileSync('./dist/geosite.dat');
        GeoSiteList.decode(buffer);
        console.log('write geosite.dat');

        let ip_list = GeoIPList.create({
            entry: [...geo_ips,
                ...Object.keys(ip_rules).map(key => {
                    let rules = ip_rules[key];
                    rules = rules.map(ip => parseIP(ip));
                    return {countryCode: key.toUpperCase(), cidr: rules}
                })
            ]
        });

        buffer = GeoIPList.encode(ip_list).finish();
        fs.writeFileSync('./dist/geoip.dat', buffer);

        buffer = fs.readFileSync('./dist/geoip.dat');
        GeoIPList.decode(buffer);
        console.log('write geoip.dat');
    } catch (error) {
        console.error(error)
    }
}

main();

import yaml
import os
import requests
import datetime
path = os.environ["WORKDIR"]

with open(path + "/lookup_plugins/alienvault-otx/dnifconfig.yml", 'r') as ymlfile:
    cfg = yaml.safe_load(ymlfile)

def execute():
    print "hello the world!"

def check_config():
    print cfg['lookup_plugin']['AVOTX_API_KEY']

api_headers = { "X-OTX-API-KEY" : cfg['lookup_plugin']['AVOTX_API_KEY'] }

def generate_domain_pulse_report(i, check_domain, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/domain/"+ check_domain + "/general"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    tlpList = []
    tagsList = []
    countriesList = []
    industriesList = []
    pulseNamesList = []
    authorsList = []
    try:
        if json_response['pulse_info']['count'] != None and json_response['pulse_info']['count'] > 0:
            i['$AVOTXPulseCount'] = json_response['pulse_info']['count']
            for pulse in json_response['pulse_info']['pulses']:
                try:
                    if pulse['TLP'] != None and not pulse['TLP'] in tlpList:
                        tlpList.append(pulse['TLP'])
                except Exception:
                    pass
                try:
                    if pulse['tags'] != None:
                        for tag in pulse['tags']:
                            if not tag in tagsList:
                                tagsList.append(tag)
                except Exception:
                    pass
                try:
                    if pulse['targeted_countries'] != None:
                        for country in pulse['targeted_countries']:
                            if not country in countriesList:
                                countriesList.append(country)
                except Exception:
                    pass
                try:
                    if pulse['targeted_industries'] != None:
                        for industry in pulse['targeted_industries']:
                            if not industry in industriesList:
                                industriesList.append(industry)
                except Exception:
                    pass
                try:
                    if pulse['name'] != None and not pulse['name'] in pulseNamesList:
                        pulseNamesList.append(pulse['name'])
                except Exception:
                    pass
                try:
                    if pulse['author']['username'] != None and not pulse['author']['username'] in authorsList:
                        authorsList.append(pulse['author']['username'])
                except Exception:
                    pass
    except Exception, e:
        pass
    if len(tlpList) > 0:
        i['$AVOTXPulseTLPs'] = tlpList
    if len(tagsList) > 0:
        i['$AVOTXPulseTags'] = tagsList
    if len(countriesList) > 0:
        i['$AVOTXPulseTargetsCountries'] = countriesList
    if len(industriesList) > 0:
        i['$AVOTXPulseTargetsIndustries'] = industriesList
    if len(pulseNamesList) > 0:
        i['$AVOTXPulseNames'] = pulseNamesList
    if len(authorsList) > 0:
        i['$AVOTXPulseAuthors'] = authorsList
    try:
        if json_response['pulse_info']['references'] != None and json_response['pulse_info']['references'] != []:
            i['$AVOTXPulseReferences'] = json_response['pulse_info']['references']
    except Exception, e:
        pass

    return i

def generate_domain_geo_report(i, check_domain, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/domain/"+ check_domain + "/geo"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['city'] != None:
            i['$AVOTXGeoCity'] = json_response['city']
    except Exception, e:
        pass
    try:
        if json_response['region'] != None:
            i['$AVOTXGeoRegion'] = json_response['region']
    except Exception, e:
        pass
    try:
        if json_response['area_code'] != None:
            i['$AVOTXGeoAreaCode'] = json_response['area_code']
    except Exception, e:
        pass
    try:
        if json_response['continent_code'] != None:
            i['$AVOTXGeoContinentCode'] = json_response['continent_code']
    except Exception, e:
        pass
    try:
        if json_response['latitude'] != None:
            i['$AVOTXGeoLatitude'] = json_response['latitude']
    except Exception, e:
        pass
    try:
        if json_response['postal_code'] != None:
            i['$AVOTXGeoPostalCode'] = json_response['postal_code']
    except Exception, e:
        pass
    try:
        if json_response['longitude'] != None:
            i['$AVOTXGeoLongitude'] = json_response['longitude']
    except Exception, e:
        pass
    try:
        if json_response['country_code'] != None:
            i['$AVOTXGeoCountryCode'] = json_response['country_code']
    except Exception, e:
        pass
    try:
        if json_response['country_name'] != None:
            i['$AVOTXGeoCountryName'] = json_response['country_name']
    except Exception, e:
        pass
    try:
        if json_response['asn'] != None:
            i['$AVOTXGeoASNCode'] = json_response['asn']
    except Exception, e:
        pass

    return i

def generate_domain_malware_report(i, check_domain, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/domain/"+ check_domain + "/malware?limit=100"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['count'] != None:
            i['$AVOTXMalwareCount'] = json_response['count']
    except Exception, e:
        pass
    hashList = []
    try:
        if json_response['data'] != None:
            for datum in json_response['data']:
                try:
                    if datum['hash'] != None and not datum['hash'] in hashList:
                        hashList.append(datum['hash'])
                except Exception:
                    pass
            if len(hashList) > 0:
                i['$AVOTXMalwareSHA256Hashes'] = hashList
    except Exception:
        pass

    return i

def generate_domain_url_report(i, check_domain, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/domain/"+ check_domain + "/url_list?limit=100"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['actual_size'] != None:
            i['$AVOTXUrlActualSize'] = json_response['actual_size']
    except Exception, e:
        pass
    urlList = []
    hostnameList = []
    ipList = []
    try:
        if json_response['url_list'] != None:
            for url_info in json_response['url_list']:
                try:
                    if url_info['url'] != None and not url_info['url'] in urlList:
                        urlList.append(url_info['url'])
                except Exception:
                    pass
                try:
                    if url_info['hostname'] != None and not url_info['hostname'] in hostnameList:
                        hostnameList.append(url_info['hostname'])
                except Exception:
                    pass
                try:
                    if url_info['result']['urlworker']['ip'] != None and not url_info['result']['urlworker']['ip'] in ipList:
                        ipList.append(url_info['result']['urlworker']['ip'])
                except Exception:
                    pass
            if len(urlList) > 0:
                i['$AVOTXUrls'] = urlList
            if len(hostnameList) > 0:
                i['$AVOTXUrlHostnames'] = hostnameList
            if len(ipList) > 0:
                i['$AVOTXUrlIPs'] = ipList
    except Exception:
        pass

    return i

def generate_domain_passivedns_report(i, check_domain, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/domain/"+ check_domain + "/passive_dns?limit=100"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['count'] != None and json_response['count'] > 0:
            i['$AVOTXPassiveDnsCount'] = json_response['count']
    except Exception, e:
        pass
    hostnameList = []
    ipList = []
    flagList = []
    try:
        if json_response['passive_dns'] != None:
            for dns_item in json_response['passive_dns']:
                try:
                    if dns_item['hostname'] != None and not dns_item['hostname'] in hostnameList:
                        hostnameList.append(dns_item['hostname'])
                except Exception:
                    pass
                try:
                    if dns_item['address'] != None and not dns_item['address'] in ipList:
                        ipList.append(dns_item['address'])
                except Exception:
                    pass
                try:
                    if dns_item['flag_title'] != None and not dns_item['flag_title'] in flagList:
                        flagList.append(dns_item['flag_title'])
                except Exception:
                    pass
            if len(hostnameList) > 0:
                i['$AVOTXPassiveDnsHostnames'] = hostnameList
            if len(ipList) > 0:
                i['$AVOTXPassiveDnsIPs'] = ipList
            if len(flagList) > 0:
                i['$AVOTXPassiveDnsCountries'] = flagList
    except Exception:
        pass

    return i

def generate_domain_whois_report(i, check_domain, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/domain/"+ check_domain + "/whois"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['data'] != None:
            for item in json_response['data']:
                try:
                    key = ( ( (item['key']).replace("_", " ") ).title() ).replace(" ", "")
                    value = item['value']
                    if key != None and value != None:
                        newkey = '$AVOTXWhois' + key
                        if newkey == "$AVOTXWhoisCreationDate" or newkey == "$AVOTXWhoisExpirationDate" or newkey == "$AVOTXWhoisUpdatedDate":
                            value = value[5:]
                            value = datetime.datetime.strptime(value, '%d %b %Y %H:%M:%S %Z').isoformat()
                            i[newkey] = value
                        else:
                            i[newkey] = value
                except Exception:
                    pass
    except Exception, e:
        pass

    return i

def generate_hash_analysis_report(i, check_hash, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/file/" + check_hash + "/analysis"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['analysis']['info']['results'] != None:
            for item in json_response['analysis']['info']['results']:
                key = ( ( (item).replace("_", " ") ).title() ).replace(" ", "").replace("Md5", "MD5").replace("Sha", "SHA")
                value = json_response['analysis']['info']['results'][item]
                if key != None and value != None:
                    newkey = '$AVOTX'+key
                    i[newkey] = value
    except Exception, e:
        pass
    ipList = []
    domainList = []
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['network']['domains'] != None:
            for item in json_response['analysis']['plugins']['cuckoo']['result']['network']['domains']:
                try:
                    if not json_response['analysis']['plugins']['cuckoo']['result']['network']['domains']['ip'] in ipList:
                        ipList.append(json_response['analysis']['plugins']['cuckoo']['result']['network']['domains']['ip'])
                except Exception:
                    pass
                try:
                    if not json_response['analysis']['plugins']['cuckoo']['result']['network']['domains']['domains'] in ipList:
                        domainList.append(json_response['analysis']['plugins']['cuckoo']['result']['network']['domains']['domain'])
                except Exception:
                    pass
    except Exception, e:
        pass

    if len(ipList) > 0:
        i['$AVOTXNetworkIPs'] = ipList
    if len(domainList) > 0:
        i['$AVOTXNetworkDomains'] = domainList;

    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['category'] != None:
            i['$AVOTXSuricataCategory'] = json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['category']
    except Exception:
        pass
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['name'] != None:
            i['$AVOTXSuricataName'] = json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['name']
    except Exception:
        pass
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['event_activity'] != None:
            i['$AVOTXSuricataEventCategory'] = json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['event_activity']
    except Exception:
        pass
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['dst_ip'] != None:
            i['$AVOTXSuricataDstIP'] = json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['dst_ip']
    except Exception:
        pass
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['dst_port'] != None:
            i['$AVOTXSuricataDstPort'] = json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['dst_port']
    except Exception:
        pass
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['cve'] != None:
            i['$AVOTXSuricataCVE'] = json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['cve']
    except Exception:
        pass
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['malware_name'] != None:
            i['$AVOTXSuricataMalwareName'] = json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['malware_name']
    except Exception:
        pass
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['subcategory'] != None:
            i['$AVOTXSuricataMalwareSubcategory'] = json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules'][0]['subcategory']
    except Exception:
        pass
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['virustotal']['total'] != None:
            i['$AVOTXVirusTotalTotalChecks'] = json_response['analysis']['plugins']['cuckoo']['result']['virustotal']['total']
    except Exception:
        pass
    try:
        if json_response['analysis']['plugins']['cuckoo']['result']['virustotal']['positives'] != None:
            i['$AVOTXVirusTotalPositives'] = json_response['analysis']['plugins']['cuckoo']['result']['suricata']['rules']['positives']
    except Exception:
        pass
    detectedList = []
    notdetectedList = []

    try:
        virustotalscans = json_response['analysis']['plugins']['cuckoo']['result']['virustotal']['scans']
        for provider in virustotalscans:
            if virustotalscans[provider]["detected"] == True:
                detectedList.append(provider)
            elif virustotalscans[provider] == False:
                notdetectedList.append(provider)
    except Exception:
        pass


    if len(detectedList) > 0:
        i["$AVOTXVirusTotalPositive"] = detectedList
    if len(notdetectedList) > 0:
        i["$AVOTXVirusTotalNegative"] = notdetectedList

    signatures = []

    try:
        virustotalscans = json_response['analysis']['plugins']['cuckoo']['result']['virustotal']['results']
        for result in virustotalscans:
            if not result["sig"] in  signatures:
                signatures.append(result["sig"])
    except Exception:
        pass

    if len(signatures) > 0:
        i["$AVOTXVirusTotalSignatures"] = signatures

    try:
        if json_response['analysis']['plugins']['adobemalwareclassifier']['results']['alerts'][0] != None:
            i['$AVOTXAdobeMalwareClassifier'] = json_response['analysis']['plugins']['adobemalwareclassifier']['results']['alerts'][0]
    except Exception, e:
        pass
    try:
        if json_response['analysis']['plugins']['avast']['results']['alerts'][0] != None:
            i['$AVOTXAvast'] = json_response['analysis']['plugins']['avast']['results']['alerts'][0]
    except Exception, e:
        pass
    try:
        if len(json_response['analysis']['plugins']['clamav']['results']) > 0:
            if json_response['analysis']['plugins']['clamav']['results']['detection'] != None:
                i['$AVOTXClamav'] = json_response['analysis']['plugins']['clamav']['results']['detection']
            else:
                i['$AVOTXClamavThreatClassifier'] = "Threat detected"
    except Exception:
        pass
    try:
        if json_response['analysis']['datetime_int'] != None:
            i['$AVOTXFirstReportDatetime'] = json_response['analysis']['datetime_int']
    except Exception, e:
        pass

    return i

def generate_hostname_pulse_report(i, check_hostname, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/hostname/"+ check_hostname + "/general"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    tlpList = []
    tagsList = []
    countriesList = []
    industriesList = []
    pulseNamesList = []
    authorsList = []
    try:
        if json_response['pulse_info']['count'] != None and json_response['pulse_info']['count'] > 0:
            i['$AVOTXPulseCount'] = json_response['pulse_info']['count']
            for pulse in json_response['pulse_info']['pulses']:
                try:
                    if pulse['TLP'] != None and not pulse['TLP'] in tlpList:
                        tlpList.append(pulse['TLP'])
                except Exception:
                    pass
                try:
                    if pulse['tags'] != None:
                        for tag in pulse['tags']:
                            if not tag in tagsList:
                                tagsList.append(tag)
                except Exception:
                    pass
                try:
                    if pulse['targeted_countries'] != None:
                        for country in pulse['targeted_countries']:
                            if not country in countriesList:
                                countriesList.append(country)
                except Exception:
                    pass
                try:
                    if pulse['targeted_industries'] != None:
                        for industry in pulse['targeted_industries']:
                            if not industry in industriesList:
                                industriesList.append(industry)
                except Exception:
                    pass
                try:
                    if pulse['name'] != None and not pulse['name'] in pulseNamesList:
                        pulseNamesList.append(pulse['name'])
                except Exception:
                    pass
                try:
                    if pulse['author']['username'] != None and not pulse['author']['username'] in authorsList:
                        authorsList.append(pulse['author']['username'])
                except Exception:
                    pass
    except Exception, e:
        pass
    if len(tlpList) > 0:
        i['$AVOTXPulseTLPs'] = tlpList
    if len(tagsList) > 0:
        i['$AVOTXPulseTags'] = tagsList
    if len(countriesList) > 0:
        i['$AVOTXPulseTargetsCountries'] = countriesList
    if len(industriesList) > 0:
        i['$AVOTXPulseTargetsIndustries'] = industriesList
    if len(pulseNamesList) > 0:
        i['$AVOTXPulseNames'] = pulseNamesList
    if len(authorsList) > 0:
        i['$AVOTXPulseAuthors'] = authorsList
    try:
        if json_response['pulse_info']['references'] != None and json_response['pulse_info']['references'] != []:
            i['$AVOTXPulseReferences'] = json_response['pulse_info']['references']
    except Exception, e:
        pass

    return i

def generate_hostname_geo_report(i, check_hostname, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/hostname/"+ check_hostname + "/geo"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['city'] != None:
            i['$AVOTXGeoCity'] = json_response['city']
    except Exception, e:
        pass
    try:
        if json_response['region'] != None:
            i['$AVOTXGeoRegion'] = json_response['region']
    except Exception, e:
        pass
    try:
        if json_response['area_code'] != None:
            i['$AVOTXGeoAreaCode'] = json_response['area_code']
    except Exception, e:
        pass
    try:
        if json_response['continent_code'] != None:
            i['$AVOTXGeoContinentCode'] = json_response['continent_code']
    except Exception, e:
        pass
    try:
        if json_response['latitude'] != None:
            i['$AVOTXGeoLatitude'] = json_response['latitude']
    except Exception, e:
        pass
    try:
        if json_response['postal_code'] != None:
            i['$AVOTXGeoPostalCode'] = json_response['postal_code']
    except Exception, e:
        pass
    try:
        if json_response['longitude'] != None:
            i['$AVOTXGeoLongitude'] = json_response['longitude']
    except Exception, e:
        pass
    try:
        if json_response['country_code'] != None:
            i['$AVOTXGeoCountryCode'] = json_response['country_code']
    except Exception, e:
        pass
    try:
        if json_response['country_name'] != None:
            i['$AVOTXGeoCountryName'] = json_response['country_name']
    except Exception, e:
        pass
    try:
        if json_response['asn'] != None:
            i['$AVOTXGeoASNCode'] = json_response['asn']
    except Exception, e:
        pass

    return i

def generate_hostname_malware_report(i, check_hostname, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/hostname/"+ check_hostname + "/malware?limit=100"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['count'] != None:
            i['$AVOTXMalwareCount'] = json_response['count']
    except Exception, e:
        pass
    hashList = []
    try:
        if json_response['data'] != None:
            for datum in json_response['data']:
                try:
                    if datum['hash'] != None and not datum['hash'] in hashList:
                        hashList.append(datum['hash'])
                except Exception:
                    pass
            if len(hashList) > 0:
                i['$AVOTXMalwareSHA256Hashes'] = hashList
    except Exception:
        pass

    return i

def generate_hostname_url_report(i, check_hostname, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/hostname/"+ check_hostname + "/url_list?limit=100"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['actual_size'] != None:
            i['$AVOTXUrlActualSize'] = json_response['actual_size']
    except Exception, e:
        pass
    urlList = []
    hostnameList = []
    ipList = []
    try:
        if json_response['url_list'] != None:
            for url_info in json_response['url_list']:
                try:
                    if url_info['url'] != None and not url_info['url'] in urlList:
                        urlList.append(url_info['url'])
                except Exception:
                    pass
                try:
                    if url_info['hostname'] != None and not url_info['hostname'] in hostnameList:
                        hostnameList.append(url_info['hostname'])
                except Exception:
                    pass
                try:
                    if url_info['result']['urlworker']['ip'] != None and not url_info['result']['urlworker']['ip'] in ipList:
                        ipList.append(url_info['result']['urlworker']['ip'])
                except Exception:
                    pass
            if len(urlList) > 0:
                i['$AVOTXUrls'] = urlList
            if len(hostnameList) > 0:
                i['$AVOTXUrlHostnames'] = hostnameList
            if len(ipList) > 0:
                i['$AVOTXUrlIPs'] = ipList
    except Exception:
        pass

    return i

def generate_hostname_passivedns_report(i, check_hostname, api_headers):

    endpoint = "https://otx.alienvault.com/api/v1/indicators/hostname/"+ check_hostname + "/passive_dns?limit=100"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['count'] != None and json_response['count'] > 0:
            i['$AVOTXPassiveDnsCount'] = json_response['count']
    except Exception, e:
        pass
    hostnameList = []
    ipList = []
    flagList = []
    try:
        if json_response['passive_dns'] != None:
            for dns_item in json_response['passive_dns']:
                try:
                    if dns_item['hostname'] != None and not dns_item['hostname'] in hostnameList:
                        hostnameList.append(dns_item['hostname'])
                except Exception:
                    pass
                try:
                    if dns_item['address'] != None and not dns_item['address'] in ipList:
                        ipList.append(dns_item['address'])
                except Exception:
                    pass
                try:
                    if dns_item['flag_title'] != None and not dns_item['flag_title'] in flagList:
                        flagList.append(dns_item['flag_title'])
                except Exception:
                    pass
            if len(hostnameList) > 0:
                i['$AVOTXPassiveDnsHostnames'] = hostnameList
            if len(ipList) > 0:
                i['$AVOTXPassiveDnsIPs'] = ipList
            if len(flagList) > 0:
                i['$AVOTXPassiveDnsCountries'] = flagList
    except Exception:
        pass

    return i

def generate_ip_geo_report(i, check_ip, api_headers):

    if ":" in check_ip:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv6/"+ check_ip + "/geo"
    else:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/"+ check_ip + "/geo"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['city'] != None:
            i['$AVOTXGeoCity'] = json_response['city']
    except Exception, e:
        pass
    try:
        if json_response['region'] != None:
            i['$AVOTXGeoRegion'] = json_response['region']
    except Exception, e:
        pass
    try:
        if json_response['area_code'] != None:
            i['$AVOTXGeoAreaCode'] = json_response['area_code']
    except Exception, e:
        pass
    try:
        if json_response['continent_code'] != None:
            i['$AVOTXGeoContinentCode'] = json_response['continent_code']
    except Exception, e:
        pass
    try:
        if json_response['latitude'] != None:
            i['$AVOTXGeoLatitude'] = json_response['latitude']
    except Exception, e:
        pass
    try:
        if json_response['postal_code'] != None:
            i['$AVOTXGeoPostalCode'] = json_response['postal_code']
    except Exception, e:
        pass
    try:
        if json_response['longitude'] != None:
            i['$AVOTXGeoLongitude'] = json_response['longitude']
    except Exception, e:
        pass
    try:
        if json_response['country_code'] != None:
            i['$AVOTXGeoCountryCode'] = json_response['country_code']
    except Exception, e:
        pass
    try:
        if json_response['country_name'] != None:
            i['$AVOTXGeoCountryName'] = json_response['country_name']
    except Exception, e:
        pass
    try:
        if json_response['asn'] != None:
            i['$AVOTXGeoASNCode'] = json_response['asn']
    except Exception, e:
        pass

    return i

def generate_ip_malware_report(i, check_ip, api_headers):

    if ":" in check_ip:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv6/"+ check_ip + "/malware?limit=100"
    else:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/"+ check_ip + "/malware?limit=100"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['count'] != None:
            i['$AVOTXMalwareCount'] = json_response['count']
    except Exception, e:
        pass
    hashList = []
    try:
        if json_response['data'] != None:
            for datum in json_response['data']:
                try:
                    if datum['hash'] != None and not datum['hash'] in hashList:
                        hashList.append(datum['hash'])
                except Exception:
                    pass
            if len(hashList) > 0:
                i['$AVOTXMalwareSHA256Hashes'] = hashList
    except Exception:
        pass

    return i

def generate_ip_url_report(i, check_ip, api_headers):

    if ":" in check_ip:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv6/"+ check_ip + "/url_list?limit=100"
    else:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/"+ check_ip + "/url_list?limit=100"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['actual_size'] != None:
            i['$AVOTXUrlActualSize'] = json_response['actual_size']
    except Exception, e:
        pass
    urlList = []
    hostnameList = []
    ipList = []
    try:
        if json_response['url_list'] != None:
            for url_info in json_response['url_list']:
                try:
                    if url_info['url'] != None and not url_info['url'] in urlList:
                        urlList.append(url_info['url'])
                except Exception:
                    pass
                try:
                    if url_info['hostname'] != None and not url_info['hostname'] in hostnameList:
                        hostnameList.append(url_info['hostname'])
                except Exception:
                    pass
                try:
                    if url_info['result']['urlworker']['ip'] != None and not url_info['result']['urlworker']['ip'] in ipList:
                        ipList.append(url_info['result']['urlworker']['ip'])
                except Exception:
                    pass
            if len(urlList) > 0:
                i['$AVOTXUrls'] = urlList
            if len(hostnameList) > 0:
                i['$AVOTXUrlHostnames'] = hostnameList
            if len(ipList) > 0:
                i['$AVOTXUrlIPs'] = ipList
    except Exception:
        pass

    return i

def generate_ip_passivedns_report(i, check_ip, api_headers):

    if ":" in check_ip:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv6/"+ check_ip + "/passive_dns?limit=100"
    else:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/"+ check_ip + "/passive_dns?limit=100"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['count'] != None and json_response['count'] > 0:
            i['$AVOTXPassiveDnsCount'] = json_response['count']
    except Exception, e:
        pass
    hostnameList = []
    ipList = []
    flagList = []
    try:
        if json_response['passive_dns'] != None:
            for dns_item in json_response['passive_dns']:
                try:
                    if dns_item['hostname'] != None and not dns_item['hostname'] in hostnameList:
                        hostnameList.append(dns_item['hostname'])
                except Exception:
                    pass
                try:
                    if dns_item['address'] != None and not dns_item['address'] in ipList:
                        ipList.append(dns_item['address'])
                except Exception:
                    pass
                try:
                    if dns_item['flag_title'] != None and not dns_item['flag_title'] in flagList:
                        flagList.append(dns_item['flag_title'])
                except Exception:
                    pass
            if len(hostnameList) > 0:
                i['$AVOTXPassiveDnsHostnames'] = hostnameList
            if len(ipList) > 0:
                i['$AVOTXPassiveDnsIPs'] = ipList
            if len(flagList) > 0:
                i['$AVOTXPassiveDnsCountries'] = flagList
    except Exception:
        pass

    return i

def generate_ip_reputation_report(i, check_ip, api_headers):

    if ":" in check_ip:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv6/"+ check_ip + "/reputation"
    else:
        endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/"+ check_ip + "/reputation"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['reputation']['threat_score'] != None:
            i['$AVOTXReputationThreatScore'] = json_response['reputation']['threat_score']
    except Exception, e:
        pass
    threatsList = []
    try:
        if json_response['reputation']['counts'] != None:
            for threatname in json_response['reputation']['counts']:
                try:
                    if not threatname in threatsList:
                        threatsList.append(threatname)
                except Exception:
                    pass
    except Exception, e:
        pass
    if len(threatsList) > 0:
        i['$AVOTXReputationThreatTypes'] = threatsList
    malActivitiesList = []
    malActivitiesCategoriesList = []
    malActivitiesSourcesList = []
    try:
        if json_response['reputation']['activities'] != None:
            for activity in json_response['reputation']['activities']:
                try:
                    if not activity['data_key'] in malActivitiesList:
                        malActivitiesList.append(activity['data_key'])
                except Exception:
                    pass
                try:
                    if not activity['name'] in malActivitiesCategoriesList:
                        malActivitiesCategoriesList.append(activity['name'])
                except Exception:
                    pass
                try:
                    if not activity['source'] in malActivitiesSourcesList:
                        malActivitiesSourcesList.append(activity['source'])
                except Exception:
                    pass
    except Exception, e:
        pass
    if len(malActivitiesList) > 0:
        i['$AVOTXReputationMalActivities'] = malActivitiesList
    if len(malActivitiesCategoriesList) > 0:
        i['$AVOTXReputationMalCategories'] = malActivitiesCategoriesList
    if len(malActivitiesSourcesList) > 0:
        i['$AVOTXReputationMalActivitiesSources'] = malActivitiesSourcesList

def generate_url_general_report(i, check_url, api_headers):

    questionmark = check_url.find('?')
    if questionmark != -1:
        check_url = check_url[0:( (questionmark) - 1)]

    endpoint = "https://otx.alienvault.com/api/v1/indicators/url/" + check_url + "/general"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['domain'] != None and json_response['domain'] != 'Unavailable':
            i['$AVOTXUrlDomain'] = json_response['domain']
            i = generate_domain_whois_report(i, json_response['domain'], api_headers)
    except Exception, e:
        pass
    try:
        if json_response['hostname'] != None and json_response['hostname'] != 'Unavailable':
            i['$AVOTXUrlHostname'] = json_response['hostname']
            i = generate_hostname_report(i, json_response['hostname'], api_headers)
    except Exception, e:
        pass
    tlpList = []
    tagsList = []
    countriesList = []
    industriesList = []
    pulseNamesList = []
    authorsList = []
    try:
        if json_response['pulse_info']['count'] != None and json_response['pulse_info']['count'] > 0:
            i['$AVOTXPulseCount'] = json_response['pulse_info']['count']
            for pulse in json_response['pulse_info']['pulses']:
                try:
                    if pulse['TLP'] != None and not pulse['TLP'] in tlpList:
                        tlpList.append(pulse['TLP'])
                except Exception:
                    pass
                try:
                    if pulse['tags'] != None:
                        for tag in pulse['tags']:
                            if not tag in tagsList:
                                tagsList.append(tag)
                except Exception:
                    pass
                try:
                    if pulse['targeted_countries'] != None:
                        for country in pulse['targeted_countries']:
                            if not country in countriesList:
                                countriesList.append(country)
                except Exception:
                    pass
                try:
                    if pulse['targeted_industries'] != None:
                        for industry in pulse['targeted_industries']:
                            if not industry in industriesList:
                                industriesList.append(industry)
                except Exception:
                    pass
                try:
                    if pulse['name'] != None and not pulse['name'] in pulseNamesList:
                        pulseNamesList.append(pulse['name'])
                except Exception:
                    pass
                try:
                    if pulse['author']['username'] != None and not pulse['author']['username'] in authorsList:
                        authorsList.append(pulse['author']['username'])
                except Exception:
                    pass
    except Exception, e:
        pass
    if len(tlpList) > 0:
        i['$AVOTXPulseTLPs'] = tlpList
    if len(tagsList) > 0:
        i['$AVOTXPulseTags'] = tagsList
    if len(countriesList) > 0:
        i['$AVOTXPulseTargetsCountries'] = countriesList
    if len(industriesList) > 0:
        i['$AVOTXPulseTargetsIndustries'] = industriesList
    if len(pulseNamesList) > 0:
        i['$AVOTXPulseNames'] = pulseNamesList
    if len(authorsList) > 0:
        i['$AVOTXPulseAuthors'] = authorsList
    try:
        if json_response['pulse_info']['references'] != None and json_response['pulse_info']['references'] != []:
            i['$AVOTXPulseReferences'] = json_response['pulse_info']['references']
    except Exception, e:
        pass

    return i

def generate_url_url_report(i, check_url, api_headers):

    questionmark = check_url.find('?')
    if questionmark != -1:
        check_url = check_url[0:( (questionmark) - 1)]

    endpoint = "https://otx.alienvault.com/api/v1/indicators/url/" + check_url + "/url_list"

    try:
        response = requests.post(endpoint, headers=api_headers)
        json_response = response.json()
    except Exception, e:
        print 'API Request Error:  %s' %e
    try:
        if json_response['city'] != None:
            i['$AVOTXGeoCity'] = json_response['city']
    except Exception, e:
        pass
    try:
        if json_response['region'] != None:
            i['$AVOTXGeoRegion'] = json_response['region']
    except Exception, e:
        pass
    try:
        if json_response['area_code'] != None:
            i['$AVOTXGeoAreaCode'] = json_response['area_code']
    except Exception, e:
        pass
    try:
        if json_response['continent_code'] != None:
            i['$AVOTXGeoContinentCode'] = json_response['continent_code']
    except Exception, e:
        pass
    try:
        if json_response['latitude'] != None:
            i['$AVOTXGeoLatitude'] = json_response['latitude']
    except Exception, e:
        pass
    try:
        if json_response['postal_code'] != None:
            i['$AVOTXGeoPostalCode'] = json_response['postal_code']
    except Exception, e:
        pass
    try:
        if json_response['longitude'] != None:
            i['$AVOTXGeoLongitude'] = json_response['longitude']
    except Exception, e:
        pass
    try:
        if json_response['country_code'] != None:
            i['$AVOTXGeoCountryCode'] = json_response['country_code']
    except Exception, e:
        pass
    try:
        if json_response['country_name'] != None:
            i['$AVOTXGeoCountryName'] = json_response['country_name']
    except Exception, e:
        pass

    for item in json_response['url_list']:
        try:
            if item['httpcode'] != None:
                try:
                    if item['result']['safebrowsing']['matches'] != None and len(item['result']['safebrowsing']['matches']) > 0:
                        i['$AVOTXGsb'] = "malware"
                except Exception:
                    pass
                try:
                    if item['result']['urlworker']['sha256'] != None:
                        i['$AVOTXSHA256Hash'] = item['result']['urlworker']['sha256']
                except Exception:
                    pass
                try:
                    if item['result']['urlworker']['md5'] != None:
                        i['$AVOTXMD5Hash'] = item['result']['urlworker']['md5']
                except Exception, e:
                    pass
                try:
                    if item['result']['urlworker']['ip'] != None:
                        i['$AVOTXResolvedIP'] = item['result']['urlworker']['ip']
                except Exception, e:
                    pass
                try:
                    if item['result']['urlworker']['filetype'] != None:
                        i['$AVOTXFileType'] = item['result']['urlworker']['filetype']
                except Exception, e:
                    pass
                try:
                    if item['result']['urlworker']['filemagic'] != None:
                        i['$AVOTXFileMagic'] = item['result']['urlworker']['filemagic']
                except Exception, e:
                    pass
                try:
                    if item['result']['urlworker']['has_file_analysis'] != None and item['result']['urlworker']['has_file_analysis'] == True and not item['result']['urlworker']['sha256']:
                        i = generate_hash_analysis_report(i, item['result']['urlworker']['sha256'], api_headers)
                except Exception, e:
                    pass
                break
        except Exception:
            pass

    return i


def get_domain_pulse_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_domain = i[var_array[0]]

            i = generate_domain_pulse_report(i, check_domain, api_headers)

    return inward_array

def get_domain_geo_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_domain = i[var_array[0]]

            i = generate_domain_geo_report(i, check_domain, api_headers)

    return inward_array

def get_domain_malware_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_domain = i[var_array[0]]

            i = generate_domain_malware_report(i, check_domain, api_headers)

    return inward_array

def get_domain_url_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_domain = i[var_array[0]]

            i = generate_domain_url_report(i, check_domain, api_headers)

    return inward_array

def get_domain_passivedns_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_domain = i[var_array[0]]

            i = generate_domain_passivedns_report(i, check_domain, api_headers)

    return inward_array

def get_domain_whois_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_domain = i[var_array[0]]

            i = generate_domain_whois_report(i, check_domain, api_headers)

    return inward_array

def get_domain_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_domain = i[var_array[0]]

            i = generate_domain_pulse_report(i, check_domain, api_headers)

            i = generate_domain_geo_report(i, check_domain, api_headers)

            i = generate_domain_malware_report(i, check_domain, api_headers)

            i = generate_domain_url_report(i, check_domain, api_headers)

            i = generate_domain_passivedns_report(i, check_domain, api_headers)

            i = generate_domain_whois_report(i, check_domain, api_headers)

    return inward_array

def get_ip_geo_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_ip = i[var_array[0]]

            i = generate_ip_geo_report(i, check_ip, api_headers)

    return inward_array

def get_ip_malware_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_ip = i[var_array[0]]

            i = generate_ip_malware_report(i, check_ip, api_headers)

    return inward_array

def get_ip_url_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_ip = i[var_array[0]]

            i = generate_ip_url_report(i, check_ip, api_headers)

    return inward_array

def get_ip_passivedns_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_ip = i[var_array[0]]

            i = generate_ip_passivedns_report(i, check_ip, api_headers)

    return inward_array

def get_ip_reputation_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_ip = i[var_array[0]]

            i = generate_ip_reputation_report(i, check_ip, api_headers)

    return inward_array

def get_ip_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_ip = i[var_array[0]]

            i = generate_ip_geo_report(i, check_ip, api_headers)

            i = generate_ip_malware_report(i, check_ip, api_headers)

            i = generate_ip_url_report(i, check_ip, api_headers)

            i = generate_ip_passivedns_report(i, check_ip, api_headers)

            i = generate_ip_reputation_report(i, check_ip, api_headers)

    return inward_array

def get_hostname_pulse_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_hostname = i[var_array[0]]

            i = generate_hostname_pulse_report(i, check_hostname, api_headers)

    return inward_array

def get_hostname_geo_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_hostname = i[var_array[0]]

            i = generate_hostname_geo_report(i, check_hostname, api_headers)

    return inward_array

def get_hostname_malware_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_hostname = i[var_array[0]]

            i = generate_hostname_malware_report(i, check_hostname, api_headers)

    return inward_array

def get_hostname_url_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_hostname = i[var_array[0]]

            i = generate_hostname_url_report(i, check_hostname, api_headers)

    return inward_array

def get_hostname_passivedns_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_hostname = i[var_array[0]]

            i = generate_hostname_passivedns_report(i, check_hostname, api_headers)

    return inward_array

def get_hostname_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_hostname = i[var_array[0]]

            i = generate_hostname_pulse_report(i, check_hostname, api_headers)

            i = generate_hostname_geo_report(i, check_hostname, api_headers)

            i = generate_hostname_malware_report(i, check_hostname, api_headers)

            i = generate_hostname_url_report(i, check_hostname, api_headers)

            i = generate_hostname_passivedns_report(i, check_hostname, api_headers)

    return inward_array

def get_url_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_url = i[var_array[0]]

            i = generate_url_general_report(i, check_url, api_headers)

            i = generate_url_url_report(i, check_url, api_headers)

    return inward_array

def get_hash_report(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            check_hash = i[var_array[0]]

            i = generate_hash_analysis_report(i, check_hash, api_headers)

    return inward_array


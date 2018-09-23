# AlienVault OTX (Open Threat Exchange)

[https://otx.alienvault.com](https://otx.alienvault.com/)

## Overview

[AlienVault Open Threat Exchange (OTX)](https://otx.alienvault.com/) is the world&#39;s most authoritative open threat information sharing and analysis network. OTX provides access to a global community of threat researchers and security professionals, with more than 50,000 participants in 140 countries, who contribute over four million threat indicators daily. OTX allows anyone in the security community to actively discuss, research, validate, and share the latest threat data, trends, and techniques.

OTX provides information on the reliability of threat information, reporter of the threat, and other details of threat investigations. OTX data can be used to enhance threat detection capabilities of security monitoring systems such as DNIF.

## AlienVault OTX lookup plugin functions

This section explains the details of the functions that can be used with the AlientVault lookup plugin.

### NOTE  
 In all the functions explained below, the examples use an event store named **testingintegrations**. This event store does not exist in DNIF by default. However, it can be created/imported. |


### get_domain_report

This function returns a complete report of all threat indicators for a given domain, including data from all the sub-reports. Data returned includes the pulse, geo, URL, passive DNS, and WHOIS analysis results.

#### Input

- Domain name

#### Example
```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvaultotx get_domain_report $Domain
```
#### Output

Click [here](https://drive.google.com/open?id=1jnymxp4w5sVJBTOxg5YN248HF4bWADAC) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Domain | Domain being queried |
| $AVOTXPulseReferences | List of URL(s) and website links that were referenced by individual OTX pulses, for the given domain |
| $AVOTXPulseCount | Number of OTX pulses that reference the given domain |
| $AVOTXPulseNames | List of titles given to pulses that reference the given domain |
| $AVOTXPulseTags | List of tags found in OTX pulses that reference the given domain |
| $AVOTXPulseTLPs | Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given domainClick [here](https://www.us-cert.gov/tlp) to know more about TLP color codes |
| $AVOTXPulseAuthors | List of authors of OTX pulses included in the report returned |
| $AVOTXGeoCity | City of the given domain&#39;s hosting server |
| $AVOTXGeoRegion | Region of the given domain&#39;s hosting server |
| $AVOTXGeoLatitude | Latitude of the location at which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoLongitude | Longitude of the location at which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoContinentCode | Continent code assigned to the location at which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoCountryName | Country in which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoASNCode | Geographic ASN code of the given domain&#39;s hosting server |
| $AVOTXGeoAreaCode | Area code assigned to the location in which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoPostalCode | Postal code assigned to the location at which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoCountryCode | Two-letter code assigned to the country in which the given domain&#39;s hosting server is deployed |
| $AVOTXMalwareCount | Number of malware samples connecting to the given domain, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes | SHA256 hashes of malware files connecting to the given domain, as analyzed by AlienVault Labs |
| $AVOTXUrlHostnames | Host names found in URL(s) analyzed by AlienVault Labs for the given domain |
| $AVOTXUrlIPs | List of IP addresses of the URL(s) in the given domain |
| $AVOTXUrlActualSize | Number of URL(s) found in the given domain |
| $AVOTXUrls | List of URL(s) in the given domain |
| $AVOTXPassiveDnsIPs | List of passive DNS IP addresses pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries | List of countries whose DNS IP addresses were pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount | Number of passive DNS IP addresses pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames | List of passive DNS host names pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXWhoisCity | WHOIS information about the city in which the given domain is registered |
| $AVOTXWhoisCountry | WHOIS information about the country in which the given domain is registered |
| $AVOTXWhoisNameServers | WHOIS information about the given domain&#39;s official nameservers |
| $AVOTXWhoisDomainName | WHOIS information about the official domain name |
| $AVOTXWhoisEmails | WHOIS information about the registered email address of the given domain (registrar&#39;s email addresses might be included) |
| $AVOTXWhoisWhoisServer | WHOIS information about the given domain&#39;s WHOIS server |
| $AVOTXWhoisDnssec | WHOIS domain name system security extensions&#39; (DNSSEC) signature state |
| $AVOTXWhoisRegistrar | WHOIS information about the name of the given domain&#39;s official registrar |
| $AVOTXWhoisAddress | WHOIS information about the given domain&#39;s official postal address |
| $AVOTXWhoisState | WHOIS information about the state in which the given domain is registered |
| $AVOTXWhoisUpdatedDate | Last update date of the WHOIS information |
| $AVOTXWhoisStatus | WHOIS information about the given domain&#39;s status code |
| $AVOTXWhoisReferralUrl | WHOIS information about the given domain&#39;s referral URL, if it exists |
| $AVOTXWhoisZipcode | WHOIS information about the zip code in which the given domain is registered |
| $AVOTXWhoisCreationDate | WHOIS information about the given domain&#39;s creation date |
| $AVOTXWhoisExpirationDate | WHOIS information about the given domain&#39;s expiry date |

### get_domain_pulse_report

This function returns threat indicators for the given domain, gathered from the OTX community&#39;s pulse stream.

#### Input

- Domain name

#### Example
```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvaultotx get_domain_pulse_report $Domain
```
#### Output

Click [here](https://drive.google.com/open?id=1AeBCjg5yiITU7adj6WMeIVDtDED1IMtc) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Domain | Domain being queried |
| $AVOTXPulseReferences | List of URL(s) and website links that were referenced by individual OTX pulses, for the given domain |
| $AVOTXPulseCount | Number of OTX pulses that reference the given domain |
| $AVOTXPulseNames | List of titles given to pulses that reference the given domain |
| $AVOTXPulseTags | List of tags found in OTX pulses that reference the given domain |
| $AVOTXPulseTLPs | Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given domainClick [here](https://www.us-cert.gov/tlp) to know more about TLP color codes |
| $AVOTXPulseAuthors | List of authors of OTX pulses included in the report returned |
| $AVOTXPulseTargetsCountries | List of countries in OTX pulses, that are targeted by this domain&#39;s malware |
| $AVOTXPulseTargetsIndustries | List of industries in OTX pulses, that are targeted by this domain&#39;s malware |

### get_domain_geo_report

This function returns registered and inferred geographic information for the given domain.

#### Input

- Domain name

#### Example
```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvaultotx get_domain_geo_report $Domain
```
#### Output

Click [here](https://drive.google.com/open?id=1yzrlGK-1Aql3uGryZ5Zbm_B-azNc9Wg-) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Domain | Domain being queried |
| $AVOTXGeoCity | City in which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoRegion | Region in which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoLatitude | Latitude of the locationat which given domain&#39;s hosting server is deployed |
| $AVOTXGeoLongitude | Longitude of the location at which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoContinentCode | Continent code assigned to the location at which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoCountryName | Country in which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoASNCode | Geographic ASN code of the given domain&#39;s hosting server |
| $AVOTXGeoAreaCode | Area code assigned to the location in which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoPostalCode | Postal code assigned to the location in which the given domain&#39;s hosting server is deployed |
| $AVOTXGeoCountryCode | Two-letter code of the country where the given domain&#39;s hosting server is deployed |

### get_domain_malware_report

This function returns malware samples connecting to the given domain, as analyzed by AlienVault Labs.

#### Input

- Domain name

#### Example
```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvaultotx get_domain_malware_report $Domain
```
#### Output

Click [here](https://drive.google.com/open?id=1eZsUaQgCRZXbv-hqFrBGOullT2xQm0fa) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Domain | Domain being queried |
| $AVOTXMalwareCount | Number of malware samples connecting to the given domain, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes | SHA256 hashes of malware files connecting to the given domain, as analyzed by AlienVault Labs |

### get_domain_url_report

This function returns a report of the URL(s) in the given domain, as analyzed by AlienVault Labs.

#### Input

- Domain name

#### Example
```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvaultotx get_domain_url_report $Domain
```
#### Output

Click [here](https://drive.google.com/open?id=1dYxNyz33X-0hvvPC9aYqrqa9v_x0B0Qa) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Domain | Domain being queried |
| $AVOTXUrlHostnames | Host names found in URL(s) analyzed by AlienVault Labs for the given domain |
| $AVOTXUrlIPs | List of IP addresses of the URL(s) for the given domain |
| $AVOTXUrlActualSize |  Number of of URL(s) found in the given domain |
| $AVOTXUrls | List of URL(s) in the given domain |

### get_domain_passivedns_report

The function returns passive DNS records pointing to the given domain, as analyzed by AlienVault Labs.

#### Input

- Domain name

#### Example
```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvaultotx get_domain_passivedns_report $Domain
```
#### Output

Click [here](https://drive.google.com/open?id=1kFHN4ur_nvDl0tWCeg2lOIbXYrpudk08) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Domain | Domain being queried |
| $AVOTXPassiveDnsIPs | List of passive DNS IP addresses pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries | List of countries whose DNS IP addresses were pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount | Number of passive DNS IP addresses pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames | List of passive DNS host names pointing to the given domain, as analyzed by AlienVault Labs |

### get_domain_whois_report

This function returns the WHOIS data captured for the given domain. Information regarding domains, related to the given domain, has not been added yet.

#### Input

- Domain name

#### Example
```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvaultotx get_domain_whois_report $Domain
```
#### Output

Click [here](https://drive.google.com/open?id=1iJLhQEZ4cqn85HaCCM0dinDTghi2mzTy) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Domain | Domain being queried |
| $AVOTXWhoisCity | WHOIS information about the city in which the given domain is registered |
| $AVOTXWhoisCountry | WHOIS information about the country in which the given domain is registered |
| $AVOTXWhoisNameServers | WHOIS information about the given domain&#39;s official nameservers |
| $AVOTXWhoisDomainName | WHOIS information about the official domain name |
| $AVOTXWhoisEmails | WHOIS information about a registered email address of the given domain (registrar&#39;s email addresses might be included) |
| $AVOTXWhoisWhoisServer | WHOIS information about the given domain&#39;s WHOIS server |
| $AVOTXWhoisDnssec | WHOIS domain name system security extensions&#39; (DNSSEC) signature state |
| $AVOTXWhoisRegistrar | WHOIS information about the name of the given domain&#39;s official registrar |
| $AVOTXWhoisAddress | WHOIS information about the given domain&#39;s official postal address |
| $AVOTXWhoisState | WHOIS information about the state in which the given domain is registered |
| $AVOTXWhoisUpdatedDate | WHOIS information about the last date on which the WHOIS information was updated |
| $AVOTXWhoisStatus | WHOIS information about the given domain&#39;s status code |
| $AVOTXWhoisReferralUrl | WHOIS information about the domain&#39;s referral URL (if it exists) |
| $AVOTXWhoisZipcode | WHOIS information about the zip code in which the given domain is registered |
| $AVOTXWhoisCreationDate | WHOIS information about the given domain&#39;s creation date |
| $AVOTXWhoisExpirationDate | WHOIS information about the given domain&#39;s expiry date |

### get_hash_report

This function returns the metadata about the file hash, as well as dynamic and static analysis of the given filehash. The SHA1, MD5, or SHA256 hashing algorithm (formats) are acceptable.

#### Input

- File hash (SHA1, MD5, or SHA256)

#### Example
```
_fetch $Filehash from testingintegrations limit 1
>>_lookup alienvaultotx get_hash_report $Filehash
```
#### Output

Click [here](https://drive.google.com/open?id=1VBSL4zYy72TxpKCioc7ycmBBXsFioYL-) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Filehash | SHA1/MD5/SHA256 file hash being queried |
| $AVOTXAdobeMalwareClassifier | Adobe Malware Classifier result for the given file hash |
| $AVOTXAvast | Avast malware analysis result for the given file hash |
| $AVOTXClamavThreatClassifier | Clamav threat classifier result for the given file hash |
| $AVOTXNetworkIPs | List of IP addresses that this hash&#39;s malware file attempts to connect to |
| $AVOTXNetworkDomains | List of domains that this hash&#39;s malware file attempts to connect to |
| $AVOTXFileClass | File class name of the given hash&#39;s malware file |
| $AVOTXFileType | File type of the given hash&#39;s malware file |
| $AVOTXFilesize | File size (in bytes) of the given hash&#39;s malware file |
| $AVOTXFirstReportDatetime | Timestamp for the first detection of the given hash&#39;s malware file, by AlienVault Labs |
| $AVOTXMD5 | MD5 hash of the given hash&#39;s malware file |
| $AVOTXSHA1 | SHA1 hash of the given hash&#39;s malware file |
| $AVOTXSHA256 | SHA256 hash of  the given hash&#39;s malware file |
| $AVOTXSsdeep | ssdeep fuzzy hash of the given hash&#39;s malware file |
| $AVOTXSuricataCVE | CVE (Common Vulnerabilities and Exposures) ID, as provided by Suricata, of the given file hash |
| $AVOTXSuricataCategory | Category, as provided by Suricata, of the given file hash. |
| $AVOTXSuricataDstIP | List of IP addresses, as provided by Suricata, that the given hash&#39;s malware file attempts to connect to |
| $AVOTXSuricataDstPort | List of ports, as provided by Suricata, that the given hash&#39;s malware file attempts to connect to |
| $AVOTXSuricataEventCategory | Event category, as provided by Suricata,  of the given hash&#39;s malware file |
| $AVOTXSuricataMalwareName | Malware name, as provided by Suricata, of the given hash&#39;s malware file |
| $AVOTXSuricataMalwareSubcategory | Subcategory, as provided by Suricata, of the given hash&#39;s malware file |
| $AVOTXSuricataName | Name, as provided by Suricata, of the given hash&#39;s malware file |
| $AVOTXVirusTotalPositive | List of threat detection services, as provided by VirusTotal,that match the given hash to a known malware |
| $AVOTXVirusTotalPositive | List of threat detection services, as provided by VirusTotal, that do not match the given hash to a known malware |
| $AVOTXVirusTotalSignatures | List of signatures, as provided by VirusTotal, that match the given hash to a known malware |
| $AVOTXVirusTotalTotalChecks | Number of threat detection services, as provided by VirusTotal that were queried for the given hash |

### get_url_report

This function returns the following information for the given URL:

- Historical geographic information
- Threat indicators gathered from the OTX community pulse stream
- AlienVault Labs&#39; URL analysis results.

#### Input

- URL

#### Example
```
_fetch $URL from testingintegrations limit 1
>>_lookup alienvaultotx get_url_report $URL
```
#### Output

Click [here](https://drive.google.com/open?id=1JvMN84a0yyqrDopqTLVrP1sIXdEqvYJA) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $URL | The URL being queried, without URL query parameters (everything after the last &#39;?&#39; is not included in the query) |
| $AVOTXFileMagic | File Magic analysis result of the given URL&#39;s destination resource |
| $AVOTXFileType | File type of the given URL&#39;s destination resource |
| $AVOTXUrlDomain | Domain name of the resource, extracted from the URL |
| $AVOTXUrlHostname | Host name of the resource, extracted from the URL |
| $AVOTXGsb | Google Safe Browsing&#39; result for the given URL |
| $AVOTXSHA256Hash | SHA256 hash of the file/resource that the URL points to |
| $AVOTXMD5Hash | MD5 Hash of the file/resource that the URL points to |
| $AVOTXResolvedIP | IP address of the server that hosts the given URL |
| $AVOTXGeoCity | City in which the given URL&#39;s hosting server is deployed |
| $AVOTXGeoRegion | Region in which the given URL&#39;s hosting server is deployed |
| $AVOTXGeoLatitude | Latitudeof the location at which the given URL&#39;s hosting server is deployed |
| $AVOTXGeoLongitude | Longitudeof the location at which the given URL&#39;s hosting server is deployed |
| $AVOTXGeoContinentCode | Continent code assigned to the location at which the given URL&#39;s hosting server is deployed |
| $AVOTXGeoCountryName | Country in which the given URL&#39;s hosting server is deployed |
| $AVOTXGeoAreaCode | Area code assigned to the location at which the given URL&#39;s hosting server is deployed |
| $AVOTXGeoPostalCode | Postal code assigned to the location at which the given URL&#39;s hosting server is deployed |
| $AVOTXGeoCountryCode | Two-letter code assigned to the country in which the given URL&#39;s hosting server is deployed |
| $AVOTXPulseReferences | List of URL(s) and website links that were referenced by individual OTX pulses, for the given URL |
| $AVOTXPulseCount | Number of OTX pulses that reference the given URL |
| $AVOTXPulseNames | List of titles given to pulses that reference the given URL |
| $AVOTXPulseTags | List of tags found in OTX pulses that reference the given URL |
| $AVOTXPulseTLPs | Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given URLClick [here](https://www.us-cert.gov/tlp) to know more about TLP color codes |
| $AVOTXPulseAuthors | List of authors of OTX pulses that are included in the report returned |
| $AVOTXPulseTargetsCountries | List of countries in OTX pulses, that are targeted by this URL&#39;s malware |
| $AVOTXPulseTargetsIndustries | List of industries in the OTX pulses, that are targeted by this URL&#39;s malware |

### get_hostname_report

This function returns a complete report of all threat indicators for a given hostname, including data from all the sub-reports. Data returned includes pulse, geo, URL, passive DNS, and WHOIS analysis.

#### Input

- Host name

#### Example
```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvaultotx get_hostname_report $Hostname
```
#### Output

Click [here](https://drive.google.com/open?id=10VUhVhdfxrdxGu6Jl9LEMieoL5Tp7uGX) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Hostname | Host name being queried |
| $AVOTXPulseReferences | List of URL(s) and website links that were referenced by individual OTX pulses, for the given host name |
| $AVOTXPulseCount | Number of OTX pulses that reference the given host name |
| $AVOTXPulseNames | List of titles given to pulses that reference the given host name |
| $AVOTXPulseTags | List of tags found in OTX pulses that reference the given host name |
| $AVOTXPulseTLPs | Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given host nameClick [here](https://www.us-cert.gov/tlp) to know more about TLP color codes |
| $AVOTXPulseAuthors | List of authors of OTX pulses included in the report returned |
| $AVOTXGeoCity | City in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoRegion | Region in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoLatitude | Latitude of the locationat which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoLongitude | Longitude of the location at which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoContinentCode | Continent code assigned to the location at which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoCountryName | Country in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoASNCode | Geographic ASN code of the location at which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoAreaCode | Area code assigned to the location in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoPostalCode | Postal code assigned to the location in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoCountryCode | Two-letter code assigned to the country in which the given host name&#39;s hosting server is deployed |
| $AVOTXMalwareCount | Number of malware samples connecting to the given host name, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes | SHA256 hashes of malware files connecting to the given host name, as analyzed by AlienVault Labs |
| $AVOTXUrlHostnames | Host names found in URL(s) analyzed by AlienVault Labs for the given host name |
| $AVOTXUrlIPs | List of IP addresses of the URL(s) for the given host name |
| $AVOTXUrlActualSize |  Number of URL(s) found for the given host name |
| $AVOTXUrls | List of URL(s) for the given host name |
| $AVOTXPassiveDnsIPs | List of passive DNS IP addresses pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries | List of countries whose DNS IP addresses were pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount | Number of passive DNS IP addresses pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames | List of passive DNS host names pointing to the given host name, as analyzed by AlienVault Labs |

### get_hostname_pulse_report

This function returns threat indicators for the given hostname, gathered from the OTX community pulse stream.

#### Input

- Host name

#### Example
```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvaultotx get_hostname_pulse_report $Hostname
```
#### Output

Click [here](https://drive.google.com/open?id=1gNoD2lwKnHPSHdfGk_9-3Hz_cDkADOSc) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Hostname | Host name being queried |
| $AVOTXPulseReferences | List of URL(s) and website links that were referenced by individual OTX pulses, for the given host name |
| $AVOTXPulseCount | Number of OTX pulses that reference the given host name |
| $AVOTXPulseNames | List of titles given to pulses that reference the given host name |
| $AVOTXPulseTags | List of tags found in OTX pulses that reference the given host name |
| $AVOTXPulseTLPs | Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given host nameClick [here](https://www.us-cert.gov/tlp) to know more about TLP color codes |
| $AVOTXPulseAuthors | List of authors of OTX pulses that are included in the report returned |
| $AVOTXPulseTargetsCountries | List of countries in OTX pulses, that are targeted by this host name&#39;s malware |
| $AVOTXPulseTargetsIndustries | List of industries in OTX pulses, that are targeted by this host name&#39;s malware |

### get_hostname_geo_report

This function returns registered and inferred geographic information for a given hostname.

#### Input

- Host name

#### Example
```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvaultotx get_hostname_geo_report $Hostname
```
#### Output

Click [here](https://drive.google.com/open?id=1508q0odc8tIIthJBlgHQqrvEc4zLRlrb) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Hostname | Hostname being queried |
| $AVOTXGeoCity | City in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoRegion | Region in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoLatitude | Latitude of the location at which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoLongitude | Longitude of the location at which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoContinentCode | Continent code assigned to the location at which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoCountryName | Country code assigned to the location in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoASNCode | Geographic ASN code of location where the given host name&#39;s hosting server is deployed |
| $AVOTXGeoAreaCode | Area code assigned to the location in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoPostalCode | Postal code assigned to the location in which the given host name&#39;s hosting server is deployed |
| $AVOTXGeoCountryCode | Two-letter code assigned to the country in which  the given host name&#39;s hosting server is deployed |

### get_hostname_malware_report

This function returns malware samples analyzed by AlienVault Labs that have been connecting to the given hostname.

#### Input

- Host name

#### Example
```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvaultotx get_hostname_malware_report $Hostname
```
#### Output

Click [here](https://drive.google.com/open?id=1nyA9uf2ung5vw1G86UTCuivb9kbO9-qX) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Hostname | Host name being queried |
| $AVOTXMalwareCount | Number of malware samples connecting to the given host name, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes | SHA256 hashes of malware files connecting to the given host name, as analyzed by AlienVault Labs |

### get_hostname_url_report

This function returns a report of the URL(s), in the given hostname, analyzed by AlienVault Labs.

#### Input

- Host name

#### Example
```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvaultotx get_hostname_url_report $Hostname
```
#### Output

Click [here](https://drive.google.com/open?id=1CZ6drOjXC4GfUiJqpsMmvpNjdc3-Tlhz) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Hostname | Host name being queried |
| $AVOTXUrlHostnames | Host names found in URL(s) analyzed by AlienVault Labs for the given host name |
| $AVOTXUrlIPs | List of IP addresses of the URL(s) for the given host name |
| $AVOTXUrlActualSize | Number of URL(s) found for the given host name |
| $AVOTXUrls | List of URL(s) for the given host name |

### get_hostname_passievdns_report

This function returns passive DNS records pointing to the given hostname, asanalyzed by AlienVault Labs.

#### Input

- Host name

#### Example
```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvaultotx get_hostname_passivedns_report $Hostname
```
#### Output

Click [here](https://drive.google.com/open?id=1SBiOmY42NU0_OmwYB-kVX1d0aLz4FWQZ) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $Hostname | Host name being queried |
| $AVOTXPassiveDnsIPs | List of passive DNS IP addresses pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries | List of countries whose DNS IP addresses point to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount | Number of passive DNS IP addresses pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames | List of passive DNS host names pointing to the given host name, as analyzed by AlienVault Labs. |

### get_ip_report

This function returns a complete report of all threat indicators for a given IP address, including data from all the sub-reports. This data returned includes pulse, geo, URL, passive DNS, and WHOIS analysis.

#### Input

- IP address (IPv4 or IPv6)

#### Example
```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvaultotx get_ip_report $SrcIP
```
#### Output

Click [here](https://drive.google.com/open?id=1jWZzrjoL8E_GE1joqim53D9R8AdsYooq) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $SrcIP | IP address being queried |
| $AVOTXReputationMalActivities | List of malicious activities that have been traced to the given IP address |
| $AVOTXReputationMalActivitiesSources | List of sources that have tracked malicious activities on the given IP address |
| $AVOTXReputationMalCategories | List of malicious activity categories that have been traced to the given IP address |
| $AVOTXReputationThreatScore | AlienVault Labs threat score for the given IP address |
| $AVOTXReputationThreatTypes | List of threat types of the malicious activities that have been traced to the given IP address |
| $AVOTXGeoCity | City in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoRegion | Region in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoLatitude | Latitude  of the location at which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoLongitude | Longitude of the location at which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoContinentCode | Continent code assigned to the location at which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoCountryName | Country in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoASNCode | Geographic ASN code of the location at which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoAreaCode | Area code assigned to the location in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoPostalCode | Postal code assigned to the location in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoCountryCode | Two-letter code assigned to the country in which the given IP address&#39; hosting server is deployed |
| $AVOTXMalwareCount | Number of malware samples connecting to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes | SHA256 hashes of malware files connecting to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXUrlHostnames | Host names found in URL(s) analyzed by AlienVault Labs for the given IP address |
| $AVOTXUrlIPs | List of IP addresses of the URL(s) for the given IP address |
| $AVOTXUrlActualSize | Number of URLs found for the given IP address |
| $AVOTXUrls | List of URL(s) for  the IP address |
| $AVOTXPassiveDnsIPs | List of passive DNS IP addresses pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries | List of countries whose DNS IP addresses were pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount | Number of passive DNS IP addresses pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames | List of passive DNS host names pointing to the given IP address, as analyzed by AlienVault Labs |

### get_ip_reputation_report

This function returns IP reputation data for the given IP address, as analyzed by AlienVault Labs using the OTX pulse stream.

#### Input

- IP address (IPv4 or IPv6)

#### Example
```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvaultotx get_ip_reputation_report $SrcIP
```
#### Output

Click [here](https://drive.google.com/open?id=1UmhULCl7-AjYH6xvWVxvST94KfgWAgIC) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $SrcIP | IP address being queried |
| $AVOTXReputationMalActivities | List of malicious activities that have been traced to the given IP address |
| $AVOTXReputationMalActivitiesSources | List of sources that have tracked malicious activities on the given IP address |
| $AVOTXReputationMalCategories | List of malicious activity categories that have been traced to the given IP address |
| $AVOTXReputationThreatScore | AlienVault Labs threat score for the given IP address |
| $AVOTXReputationThreatTypes | List of threat types of the malicious activities that have been traced to the given IP address |

### get_ip_geo_report

This function returns registered and inferred geographic information for a given IP address.

#### Input

- IP address (IPv4 or IPv6)

#### Example
```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvaultotx get_ip_geo_report $SrcIP
```
#### Output

Click [here](https://drive.google.com/open?id=1oiWY0mgR6l1Ryd8osoYPHNnjcHvg0T8K) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $SrcIP | IP address being queried |
| $AVOTXGeoCity | City in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoRegion | Region in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoLatitude | Latitude of the location at which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoLongitude | Longitude of the location at which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoContinentCode | Continent code assigned to the location at which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoCountryName | Country in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoASNCode | Geographic ASN code of the location at which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoAreaCode | Area code assigned to the location in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoPostalCode | Postal code assigned to the location in which the given IP address&#39; hosting server is deployed |
| $AVOTXGeoCountryCode | Two letter code assigned to the country in which the IP address&#39; hosting server is deployed |

### get_ip_malware_report

This function returns malware samples connecting to the given IP address, as analyzed by AlienVault Labs.

#### Input

- IP address (IPv4 or IPv6)

#### Example
```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvaultotx get_ip_malware_report $SrcIP
```
#### Output

Click [here](https://drive.google.com/open?id=1GrOQOl9xbemGxkRMApu1S9MlUpiLCA8B) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $SrcIP | IP address being queried |
| $AVOTXMalwareCount | Number of malware samples connecting to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes | SHA256 hashes of malware files connecting to the given IP address, as analyzed by AlienVault Labs |

### get_ip_url_report

This function returns a report of the URL(s) on the given IP, as analyzed by AlienVault Labs.

#### Input

- IP address (IPv4 or IPv6)

#### Example
```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvaultotx get_ip_url_report $SrcIP
```
#### Output

Click [here](https://drive.google.com/open?id=1FqO6vPs2sRyxnRmIzSrK1X2KGTw9Dc2o) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $SrcIP | IP address being queried |
| $AVOTXUrlHostnames | Host names found in URL(s) analyzed by AlienVault Labs for the given IP address |
| $AVOTXUrlIPs | List of IP addresses of the URL(s) for the IP address |
| $AVOTXUrlActualSize | Number of URL(s) found for the given IP address |
| $AVOTXUrls | List of URL(s) for the given IP address |

### get_ip_passivedns_report

This function returns passive DNS records pointing to the given IP address, as analyzed by AlienVault Labs.

#### Input

- IP address (IPv4 or IPv6)

#### Example
```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvaultotx get_ip_passivedns_report $SrcIP
```
#### Output

Click [here](https://drive.google.com/open?id=1IWXxSeeVQ4yJ4_YllvO4UZXo29sO6rWX) to view the output of the above example.

The output of the **lookup** call has the following structure (for the available data):

| **Field** | **Description** |
| --- | --- |
| $SrcIP | IP address being queried |
| $AVOTXPassiveDnsIPs | List of passive DNS IP addresses pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries | List of countries whose DNS IP addresses point to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount | Number of passive DNS IP addresses pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames | List of passive DNS host names pointing to the given IP address, as analyzed by AlienVault Labs |

## Using the AlienVault OTX API with DNIF

The AlienVault OTX API can be found on the AlienVault website at [https://otx.alienvault.com/api](https://otx.alienvault.com/api).

**Getting started with AlienVault OTX API with DNIF**

1.Login to your Data Store, Correlator, and A10 containers.

[ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)

2.Move to the  `**/dnif/<Deployment-key>/lookup_plugins**`  folder path.

$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/

3.Clone using the following command:

git clone https://github.com/dnif/lookup-alienvault-otx.git alienvault-otx

4.Navigate to the  `**/dnif/<Deployment-key>/lookup_plugins/alienvault-otx/**`  folder path and open the **dnifconfig.yml** configuration file

5. Replace the tag <**Add_your_api_key_here** > with your AlienVault API key that can be generated at [https://otx.alienvault.com](https://otx.alienvault.com/)

lookup_plugin:

  AVOTX_API_KEY: <Add_your_api_key_here>

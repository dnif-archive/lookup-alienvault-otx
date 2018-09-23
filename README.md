# AlienVault OTX (Open Threat Exchange)

https://otx.alienvault.com

## Overview

[AlienVault Open Threat Exchange (OTX)](https://otx.alienvault.com) is the world’s most authoritative open threat information sharing and analysis network. OTX provides access to a global community of threat researchers and security professionals, with more than 50,000 participants in 140 countries, who contribute over four million threat indicators daily. OTX allows anyone in the security community to actively discuss, research, validate, and share the latest threat data, trends, and techniques.
OTX provides information on the reliability of threat information, reporter of the threat, and other details of threat investigations. OTX data can be used to enhance threat detection capabilities of security monitoring systems such as DNIF.

## AlienVault OTX lookup plugin functions

This section explains the details of the functions that can be used with the AlientVault lookup plugin.

##### Note

In all the functions explained below, the examples use an event store named `testingintegrations`. This event store does not exist in DNIF by default. However, it can be created/imported.

### Retrieve Domain Report

This function returns a complete report of all threat indicators for a given domain, including data from all the sub-reports. Data returned includes the pulse, geo, URL, passive DNS, and WHOIS analysis results.

- input : A Domain name

```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvault-otx get_domain_report $Domain
```

###### Sample walkthrough video for domain report

[Get Domain Report Walkthrough Video](https://drive.google.com/open?id=1jnymxp4w5sVJBTOxg5YN248HF4bWADAC)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Domain| Domain being queried |
| $AVOTXPulseReferences| List of URL(s) and website links that were referenced by individual OTX pulses, for the given domain |
| $AVOTXPulseCount| Number of OTX pulses that reference the given domain |
| $AVOTXPulseNames| List of titles given to pulses that reference the given domain |
| $AVOTXPulseTags| List of tags found in OTX pulses that reference the given domain |
| $AVOTXPulseTLPs| Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given domain. Click [here](https://www.us-cert.gov/tlp) to know more about TLP color codes|
| $AVOTXPulseAuthors| List of authors of OTX pulses included in the report returned |
| $AVOTXGeoCity| City of the given domain's hosting server |
| $AVOTXGeoRegion| Region of the given domain's hosting server |
| $AVOTXGeoLatitude| Latitude of the location at which the given domain's hosting server is deployed |
| $AVOTXGeoLongitude| Longitude of the location at which the given domain's hosting server is deployed |
| $AVOTXGeoContinentCode| Continent code assigned to the location at which the given domain's hosting server is deployed |
| $AVOTXGeoCountryName| Country in which the given domain's hosting server is deployed |
| $AVOTXGeoASNCode| Geographic ASN code of the given domain’s hosting server |
| $AVOTXGeoAreaCode| Area code assigned to the location in which the given domain's hosting server is deployed |
| $AVOTXGeoPostalCode| Postal code assigned to the location at which the given domain's hosting server is deployed |
| $AVOTXGeoCountryCode| Two-letter code assigned to the country in which the given domain's hosting server is deployed |
| $AVOTXMalwareCount| Number of malware samples connecting to the given domain, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes| SHA256 hashes of malware files connecting to the given domain, as analyzed by AlienVault Labs |
| $AVOTXUrlHostnames| Host names found in URL(s) analyzed by AlienVault Labs for the given domain |
| $AVOTXUrlIPs| List of IP addresses of the URL(s) in the given domain |
| $AVOTXUrlActualSize| Number of URL(s) found in the given domain |
| $AVOTXUrls| List of URL(s) in the given domain |
| $AVOTXPassiveDnsIPs| List of passive DNS IP addresses pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries| List of countries whose DNS IP addresses were pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount| Number of passive DNS IP addresses pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames| List of passive DNS host names pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXWhoisCity| WHOIS information about the city in which the given domain is registered |
| $AVOTXWhoisCountry| WHOIS information about the country in which the given domain is registered |
| $AVOTXWhoisNameServers| WHOIS information about the given domain's official nameservers |
| $AVOTXWhoisDomainName| WHOIS information about the official domain name |
| $AVOTXWhoisEmails| WHOIS information about the registered email address of the given domain (registrar's email addresses might be included) |
| $AVOTXWhoisWhoisServer| WHOIS information about the given domain's WHOIS server |
| $AVOTXWhoisDnssec| WHOIS domain name system security extensions’ (DNSSEC) signature state |
| $AVOTXWhoisRegistrar| WHOIS information about the name of the given domain's official registrar |
| $AVOTXWhoisAddress| WHOIS information about the given domain's official postal address |
| $AVOTXWhoisState| WHOIS information about the state in which the given domain is registered |
| $AVOTXWhoisUpdatedDate| Last update date of the WHOIS information |
| $AVOTXWhoisStatus| WHOIS information about the given domain’s status code |
| $AVOTXWhoisReferralUrl| WHOIS information about the given domain's referral URL, if it exists |
| $AVOTXWhoisZipcode| WHOIS information about the zip code in which the given domain is registered |
| $AVOTXWhoisCreationDate| WHOIS information about the given domain's creation date |
| $AVOTXWhoisExpirationDate| WHOIS information about the given domain's expiration date |

### Retrieve Domain Pulse Report

Threat indicators for the given domain, gathered from the OTX community pulse stream.

- input : A Domain name

```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvault-otx get_domain_pulse_report $Domain
```

###### Sample walkthrough video for domain pulse report

[Get Domain Pulse Report Walkthrough Video](https://drive.google.com/open?id=1AeBCjg5yiITU7adj6WMeIVDtDED1IMtc)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Domain| Domain being queried |
| $AVOTXPulseReferences| List of URL(s) and website links that were referenced by individual OTX pulses, for the given domain |
| $AVOTXPulseCount| Number of OTX pulses that reference the given domain |
| $AVOTXPulseNames| List of titles given to pulses that reference the given domain |
| $AVOTXPulseTags| List of tags found in OTX pulses that reference the given domain |
| $AVOTXPulseTLPs| Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given domain. Click [here](https://www.us-cert.gov/tlp) to know more about TLP color codes|
| $AVOTXPulseAuthors| List of authors of OTX pulses included in the report returned |
| $AVOTXPulseTargetsCountries| List of countries in OTX pulses, that are targeted by this domain's malware |
| $AVOTXPulseTargetsIndustries| List of industries in OTX pulses, that are targeted by this domain's malware |

### Retrieve Domain Geo Report

Registered and inferred geographic information for a given domain (city, country, postal etc).

- input : A Domain name

```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvault-otx get_domain_geo_report $Domain
```

###### Sample walkthrough video for domain geo report

[Get Domain Geo Report Walkthrough Video](https://drive.google.com/open?id=1yzrlGK-1Aql3uGryZ5Zbm_B-azNc9Wg-)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Domain| Domain being queried |
| $AVOTXGeoCity| City of the given domain's hosting server |
| $AVOTXGeoRegion| Region of the given domain's hosting server |
| $AVOTXGeoLatitude| Latitude of the location at which the given domain's hosting server is deployed |
| $AVOTXGeoLongitude| Longitude of the location at which the given domain's hosting server is deployed |
| $AVOTXGeoContinentCode| Continent code assigned to the location at which the given domain's hosting server is deployed |
| $AVOTXGeoCountryName| Country in which the given domain's hosting server is deployed |
| $AVOTXGeoASNCode| Geographic ASN code of the given domain’s hosting server |
| $AVOTXGeoAreaCode| Area code assigned to the location in which the given domain's hosting server is deployed |
| $AVOTXGeoPostalCode| Postal code assigned to the location at which the given domain's hosting server is deployed |
| $AVOTXGeoCountryCode| Two-letter code assigned to the country in which the given domain's hosting server is deployed |

### Retrieve Domain Malware Report

Malware samples analyzed by AlienVault Labs which have been observed connecting to the given domain.

- input : A Domain name

```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvault-otx get_domain_malware_report $Domain
```

###### Sample walkthrough video for domain malware report

[Get Domain Malware Report Walkthrough Video](https://drive.google.com/open?id=1eZsUaQgCRZXbv-hqFrBGOullT2xQm0fa)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Domain| Domain being queried |
| $AVOTXMalwareCount| Number of malware samples connecting to the given domain, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes| SHA256 hashes of malware files connecting to the given domain, as analyzed by AlienVault Labs |

### Retrieve Domain URL Report

Report of the URLs analyzed by AlienVault Labs on the given domain.

- input : A Domain name

```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvault-otx get_domain_url_report $Domain
```

###### Sample walkthrough video for domain URL report

[Get Domain URL Report Walkthrough Video](https://drive.google.com/open?id=1dYxNyz33X-0hvvPC9aYqrqa9v_x0B0Qa)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Domain| Domain being queried |
| $AVOTXUrlHostnames| Host names found in URL(s) analyzed by AlienVault Labs for the given domain |
| $AVOTXUrlIPs| List of IP addresses of the URL(s) in the given domain |
| $AVOTXUrlActualSize| Number of URL(s) found in the given domain |
| $AVOTXUrls| List of URL(s) in the given domain |

### Retrieve Domain Passive DNS Report

Passive DNS records observed by AlienVault to be pointing to the given domain.

- input : A Domain name

```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvault-otx get_domain_passivedns_report $Domain
```

###### Sample walkthrough video for domain passive DNS report

[Get Domain Passive DNS Report Walkthrough Video](https://drive.google.com/open?id=1kFHN4ur_nvDl0tWCeg2lOIbXYrpudk08)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Domain| Domain being queried |
| $AVOTXPassiveDnsIPs| List of passive DNS IP addresses pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries| List of countries whose DNS IP addresses were pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount| Number of passive DNS IP addresses pointing to the given domain, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames| List of passive DNS host names pointing to the given domain, as analyzed by AlienVault Labs |

### Retrieve Domain WHOIS Report

WHOIS data captured for the given domain only (information regarding domains related to the given domain has not been added yet)

- input : A Domain name

```
_fetch $Domain from testingintegrations limit 1
>>_lookup alienvault-otx get_domain_whois_report $Domain
```

###### Sample walkthrough video for domain WHOIS report

[Get Domain WHOIS Report Walkthrough Video](https://drive.google.com/open?id=1iJLhQEZ4cqn85HaCCM0dinDTghi2mzTy)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Domain| Domain being queried |
| $AVOTXWhoisCity| WHOIS information about the city in which the given domain is registered |
| $AVOTXWhoisCountry| WHOIS information about the country in which the given domain is registered |
| $AVOTXWhoisNameServers| WHOIS information about the given domain's official nameservers |
| $AVOTXWhoisDomainName| WHOIS information about the official domain name |
| $AVOTXWhoisEmails| WHOIS information about the registered email address of the given domain (registrar's email addresses might be included) |
| $AVOTXWhoisWhoisServer| WHOIS information about the given domain's WHOIS server |
| $AVOTXWhoisDnssec| WHOIS domain name system security extensions’ (DNSSEC) signature state |
| $AVOTXWhoisRegistrar| WHOIS information about the name of the given domain's official registrar |
| $AVOTXWhoisAddress| WHOIS information about the given domain's official postal address |
| $AVOTXWhoisState| WHOIS information about the state in which the given domain is registered |
| $AVOTXWhoisUpdatedDate| Last update date of the WHOIS information |
| $AVOTXWhoisStatus| WHOIS information about the given domain’s status code |
| $AVOTXWhoisReferralUrl| WHOIS information about the given domain's referral URL, if it exists |
| $AVOTXWhoisZipcode| WHOIS information about the zip code in which the given domain is registered |
| $AVOTXWhoisCreationDate| WHOIS information about the given domain's creation date |
| $AVOTXWhoisExpirationDate| WHOIS information about the given domain's expiration date |

### Retrieve Filehash Report

Metadata about the file hash, as well as dynamic and static analysis of the given filehash (SHA1, MD5, or SHA256 acceptable)

- input : A file hash in SHA1, MD5, or SHA256 format

```
_fetch $Filehash from testingintegrations limit 1
>>_lookup alienvault-otx get_hash_report $Filehash
```

###### Sample walkthrough video for filehash report

[Get Hash Report Walkthrough Video](https://drive.google.com/open?id=1VBSL4zYy72TxpKCioc7ycmBBXsFioYL-)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Filehash| The SHA1/MD5/SHA256 file hash being queried |
| $AVOTXAdobeMalwareClassifier| Adobe Malware Classifier result for the given file hash |
| $AVOTXAvast| Avast malware analysis result for the given file hash |
| $AVOTXClamavThreatClassifier| Clamav threat classifier result for the given file hash |
| $AVOTXNetworkIPs| List of IP addresses that this hash's malware file attempts to connect to |
| $AVOTXNetworkDomains| List of domains that this hash's malware file attempts to connect to |
| $AVOTXFileClass| File class name for the given hash's malware file |
| $AVOTXFileType| File type for the given hash's malware file |
| $AVOTXFilesize| File size (in bytes) of the given hash's malware file |
| $AVOTXFirstReportDatetime| Timestamp for the first detection of the given hash's malware file, by AlienVault Labs |
| $AVOTXMD5| MD5 hash for the given hash's malware file |
| $AVOTXSHA1| SHA1 hash for the given hash's malware file |
| $AVOTXSHA256| SHA256 hash for the given hash's malware file |
| $AVOTXSsdeep| ssdeep fuzzy hash of the given hash's malware file |
| $AVOTXSuricataCVE| CVE (Common Vulnerabilities and Exposures) ID, as provided by Suricata, of the given file hash |
| $AVOTXSuricataCategory| Category, as provided by Suricata, of the given file hash |
| $AVOTXSuricataDstIP| List of IP addresses, as provided by Suricata, that the given hash's malware file attempts to connect to |
| $AVOTXSuricataDstPort| List of ports, as provided by Suricata, that the given hash’s malware file attempts to connect to |
| $AVOTXSuricataEventCategory| Event category, as provided by Suricata,  of the given hash's malware file |
| $AVOTXSuricataMalwareName| Malware name, as provided by Suricata, of the given hash's malware file |
| $AVOTXSuricataMalwareSubcategory| Subcategory, as provided by Suricata, of the given hash's malware file |
| $AVOTXSuricataName| Name, as provided by Suricata, of the given hash's malware file |
| $AVOTXVirusTotalPositive| List of threat detection services, as provided by VirusTotal, that match the given hash to a known malware  |
| $AVOTXVirusTotalPositive| List of threat detection services, as provided by VirusTotal, that do not match the given hash to a known malware |
| $AVOTXVirusTotalSignatures| List of signatures, as provided by VirusTotal, that match the given hash to a known malware |
| $AVOTXVirusTotalTotalChecks| Number of threat detection services, as provided by VirusTotal that were queried for the given hash |

### Retrieve URL Report

This function returns historical geographic information, threat indicators gathered from the OTX community pulse stream, and AlienVault Labs' URL analysis results for the given URL.

- input : A URL

```
_fetch $URL from testingintegrations limit 1
>>_lookup alienvault-otx get_url_report $URL
```

###### Sample walkthrough video for URL report

[Get URL Report Walkthrough Video](https://drive.google.com/open?id=1JvMN84a0yyqrDopqTLVrP1sIXdEqvYJA)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $URL| The URL being queried, without URL query parameters (everything after the last ‘?’ is not included in the query) |
| $AVOTXFileMagic| File Magic analysis result of the given URL's destination resource |
| $AVOTXFileType| File type of the given URL's destination resource |
| $AVOTXUrlDomain| Domain name of the resource, extracted from the URL |
| $AVOTXUrlHostname| Hostname of the resource, extracted from the URL |
| $AVOTXGsb| Google Safe Browsing result about the given URL |
| $AVOTXSHA256Hash| SHA256 Hash of the file/resource that the URL points to |
| $AVOTXMD5Hash| MD5 Hash of the file/resource that the URL points to |
| $AVOTXResolvedIP| The IP address of the server that hosts the given URL |
| $AVOTXGeoCity| City in which the given URL's hosting server is deployed |
| $AVOTXGeoRegion| Region in which the given URL's hosting server is deployed |
| $AVOTXGeoLatitude| Latitude of the location at which the given URL's hosting server is deployed |
| $AVOTXGeoLongitude| Longitude of the location at which the given URL's hosting server is deployed |
| $AVOTXGeoContinentCode| Continent code assigned to the location at which the given URL's hosting server is deployed |
| $AVOTXGeoCountryName| Country in which the given URL's hosting server is deployed |
| $AVOTXGeoAreaCode| Area code assigned to the location at which the given URL's hosting server is deployed |
| $AVOTXGeoPostalCode| Postal code assigned to the location at which the given URL's hosting server is deployed |
| $AVOTXGeoCountryCode| Two-letter code assigned to the country in which the given URL's hosting server is deployed |
| $AVOTXPulseReferences| List of URL(s) and website links that were referenced by individual OTX pulses, for the given URL |
| $AVOTXPulseCount| Number of OTX pulses that reference the given URL |
| $AVOTXPulseNames| List of titles given to pulses that reference the given URL |
| $AVOTXPulseTags| List of tags found in OTX pulses that reference the given URL |
| $AVOTXPulseTLPs| Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given URL. Click [here](https://www.us-cert.gov/tlp) to know more about TLP color codes |
| $AVOTXPulseAuthors| List of authors of OTX pulses that are included in the report returned |
| $AVOTXPulseTargetsCountries| List of countries in OTX pulses, that are targeted by this URL's malware |
| $AVOTXPulseTargetsIndustries| List of industries in the OTX pulses, that are targeted by this URL's malware |

### Retrieve Hostname Report

This function returns a complete report of all threat indicators for a given hostname, including data from all the sub-reports. Data returned includes pulse, geo, URL, passive DNS, and WHOIS analysis.

- input : A Host name

```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvault-otx get_hostname_report $Hostname
```

###### Sample walkthrough video for hostname report

[Get Hostname Report Walkthrough Video](https://drive.google.com/open?id=10VUhVhdfxrdxGu6Jl9LEMieoL5Tp7uGX)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Hostname| Hostname being queried |
| $AVOTXPulseReferences| List of URL(s) and website links that were referenced by individual OTX pulses, for the given host name |
| $AVOTXPulseCount| Number of OTX pulses that reference the given host name |
| $AVOTXPulseNames| List of titles given to pulses that reference the given host name |
| $AVOTXPulseTags| List of tags found in OTX pulses that reference the given host name |
| $AVOTXPulseTLPs| Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given host name. Click [here](https://www.us-cert.gov/tlp) to know more about TLP color codes |
| $AVOTXPulseAuthors| List of authors of OTX pulses included in the report returned |
| $AVOTXGeoCity| City in which the given host name's hosting server is deployed |
| $AVOTXGeoRegion| Region in which the given host name's hosting server is deployed |
| $AVOTXGeoLatitude| Latitude of the location at which the given host name's hosting server is deployed |
| $AVOTXGeoLongitude| Longitude of the location at which the given host name's hosting server is deployed |
| $AVOTXGeoContinentCode| Continent code assigned to the location at which the given host name's hosting server is deployed |
| $AVOTXGeoCountryName| Country in which the given host name's hosting server is deployed |
| $AVOTXGeoASNCode| Geographic ASN code of the location at which the given host name’s hosting server is deployed |
| $AVOTXGeoAreaCode| Area code assigned to the location in which the given host name's hosting server is deployed |
| $AVOTXGeoPostalCode| Postal code assigned to the location in which the given host name's hosting server is deployed |
| $AVOTXGeoCountryCode| Two-letter code assigned to the country in which the given host name's hosting server is deployed |
| $AVOTXMalwareCount| Number of malware samples connecting to the given host name, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes| SHA256 hashes of malware files connecting to the given host name, as analyzed by AlienVault Labs |
| $AVOTXUrlHostnames| Host names found in URL(s) analyzed by AlienVault Labs for the given host name |
| $AVOTXUrlIPs| List of IP addresses of the URL(s) for the given host name |
| $AVOTXUrlActualSize| Number of URL(s) found for the given host name |
| $AVOTXUrls| List of URL(s) for the given host name |
| $AVOTXPassiveDnsIPs| List of passive DNS IP addresses pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries| List of countries whose DNS IP addresses were pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount| Number of passive DNS IP addresses pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames| List of passive DNS host names pointing to the given host name, as analyzed by AlienVault Labs |

### Retrieve Hostname Pulse Report

Threat indicators for the given hostname, gathered from the OTX community pulse stream.

- input : A Hostname

```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvault-otx get_hostname_pulse_report $Hostname
```

###### Sample walkthrough video for hostname pulse report

[Get Hostname Pulse Report Walkthrough Video](https://drive.google.com/open?id=1gNoD2lwKnHPSHdfGk_9-3Hz_cDkADOSc)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Hostname| Hostname being queried |
| $AVOTXPulseReferences| List of URL(s) and website links that were referenced by individual OTX pulses, for the given host name |
| $AVOTXPulseCount| Number of OTX pulses that reference the given host name |
| $AVOTXPulseNames| List of titles given to pulses that reference the given host name |
| $AVOTXPulseTags| List of tags found in OTX pulses that reference the given host name |
| $AVOTXPulseTLPs| Traffic Light Protocol (TLP) color code category of OTX pulses that reference the given host name. Click [here](https://www.us-cert.gov/tlp) to know more about TLP color codes |
| $AVOTXPulseAuthors| List of authors of OTX pulses included in the report returned |
| $AVOTXPulseTargetsCountries| List of countries in OTX pulses, that are targeted by this host name's malware |
| $AVOTXPulseTargetsIndustries| List of industries in OTX pulses, that are targeted by this host name's malware |

### Retrieve Hostname Geo Report

Registered and inferred geographic information for a given hostname (city, country, postal etc).

- input : A Hostname

```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvault-otx get_hostname_geo_report $Hostname
```

###### Sample walkthrough video for hostname geo report

[Get Hostname Geo Report Walkthrough Video](https://drive.google.com/open?id=1508q0odc8tIIthJBlgHQqrvEc4zLRlrb)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Hostname| Hostname being queried |
| $AVOTXGeoCity| City in which the given host name's hosting server is deployed |
| $AVOTXGeoRegion| Region in which the given host name's hosting server is deployed |
| $AVOTXGeoLatitude| Latitude of the location at which the given host name's hosting server is deployed |
| $AVOTXGeoLongitude| Longitude of the location at which the given host name's hosting server is deployed |
| $AVOTXGeoContinentCode| Continent code assigned to the location at which the given host name's hosting server is deployed |
| $AVOTXGeoCountryName| Country in which the given host name's hosting server is deployed |
| $AVOTXGeoASNCode| Geographic ASN code of the location at which the given host name’s hosting server is deployed |
| $AVOTXGeoAreaCode| Area code assigned to the location in which the given host name's hosting server is deployed |
| $AVOTXGeoPostalCode| Postal code assigned to the location in which the given host name's hosting server is deployed |
| $AVOTXGeoCountryCode| Two-letter code assigned to the country in which the given host name's hosting server is deployed |

### Retrieve Hostname Malware Report

Malware samples analyzed by AlienVault Labs which have been observed connecting to the given hostname.

- input : A Hostname

```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvault-otx get_hostname_malware_report $Hostname
```

###### Sample walkthrough video for hostname malware report

[Get Hostname Malware Report Walkthrough Video](https://drive.google.com/open?id=1nyA9uf2ung5vw1G86UTCuivb9kbO9-qX)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Hostname| Hostname being queried |
| $AVOTXMalwareCount| Number of malware samples connecting to the given host name, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes| SHA256 hashes of malware files connecting to the given host name, as analyzed by AlienVault Labs |

### Retrieve Hostname URL Report

Report of the URLs analyzed by AlienVault Labs on the given hostname.

- input : A Hostname

```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvault-otx get_hostname_url_report $Hostname
```

###### Sample walkthrough video for hostname URL report

[Get Hostname URL Report Walkthrough Video](https://drive.google.com/open?id=1CZ6drOjXC4GfUiJqpsMmvpNjdc3-Tlhz)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Hostname| Hostname being queried |
| $AVOTXUrlHostnames| Host names found in URL(s) analyzed by AlienVault Labs for the given host name |
| $AVOTXUrlIPs| List of IP addresses of the URL(s) for the given host name |
| $AVOTXUrlActualSize| Number of URL(s) found for the given host name |
| $AVOTXUrls| List of URL(s) for the given host name |

### Retrieve Hostname Passive DNS Report

Passive DNS records observed by AlienVault to be pointing to the given hostname.

- input : A Hostname

```
_fetch $Hostname from testingintegrations limit 1
>>_lookup alienvault-otx get_hostname_passivedns_report $Hostname
```

###### Sample walkthrough video for hostname passive DNS report

[Get Hostname Passive DNS Report Walkthrough Video](https://drive.google.com/open?id=1SBiOmY42NU0_OmwYB-kVX1d0aLz4FWQZ)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Hostname| Hostname being queried |
| $AVOTXPassiveDnsIPs| List of passive DNS IP addresses pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries| List of countries whose DNS IP addresses were pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount| Number of passive DNS IP addresses pointing to the given host name, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames| List of passive DNS host names pointing to the given host name, as analyzed by AlienVault Labs |

### Retrieve IP Report

Complete report of all threat indicators for a given IP, including data from all the sub reports. Data returned includes pulse, geo, URL, passive DNS, and WHOIS analysis.

- input : A IPv4 or IPv6 address

```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvault-otx get_ip_report $SrcIP
```

###### Sample walkthrough video for IP report

[Get IP Report Walkthrough Video](https://drive.google.com/open?id=1jWZzrjoL8E_GE1joqim53D9R8AdsYooq)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $SrcIP| IP being queried |
| $AVOTXReputationMalActivities| List of malicious activities that have been traced to the given IP address |
| $AVOTXReputationMalActivitiesSources| List of sources that have tracked malicious activities on the given IP address |
| $AVOTXReputationMalCategories| List of malicious activity categories that have been traced to the given IP address |
| $AVOTXReputationThreatScore| AlienVault Labs threat score for the given IP address |
| $AVOTXReputationThreatTypes| List of threat types of the malicious activities that have been traced to the given IP address |
| $AVOTXGeoCity| City in which the given IP address’ hosting server is deployed |
| $AVOTXGeoRegion| Region in which the given IP address’ hosting server is deployed |
| $AVOTXGeoLatitude| Latitude of the location at which the given IP address’ hosting server is deployed |
| $AVOTXGeoLongitude| Longitude of the location at which the given IP address’ hosting server is deployed |
| $AVOTXGeoContinentCode| Continent code assigned to the location at which the given IP address’ hosting server is deployed |
| $AVOTXGeoCountryName| Country in which the given IP address’ hosting server is deployed |
| $AVOTXGeoASNCode| Geographic ASN code of the location at which the given IP address’ hosting server is deployed |
| $AVOTXGeoAreaCode| Area code assigned to the location in which the given IP address’ hosting server is deployed |
| $AVOTXGeoPostalCode| Postal code assigned to the location in which the given IP address’ hosting server is deployed |
| $AVOTXGeoCountryCode| Two-letter code assigned to the country in which the given IP address’ hosting server is deployed |
| $AVOTXMalwareCount| Number of malware samples connecting to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes| SHA256 hashes of malware files connecting to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXUrlHostnames| Host names found in URL(s) analyzed by AlienVault Labs for the given IP address |
| $AVOTXUrlIPs| List of IP addresses of the URL(s) for the given IP address |
| $AVOTXUrlActualSize| Number of URLs found for the given IP address |
| $AVOTXUrls| List of URL(s) for the IP address |
| $AVOTXPassiveDnsIPs| List of passive DNS IP addresses pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries| List of countries whose DNS IP addresses were pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount| Number of passive DNS IP addresses pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames| List of passive DNS host names pointing to the given IP address, as analyzed by AlienVault Labs |

### Retrieve IP Reputation Report

OTX data on malicious activity observed by AlienVault Labs (IP Reputation).

- input : A IPv4 or IPv6 address

```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvault-otx get_ip_reputation_report $SrcIP
```

###### Sample walkthrough video for IP reputation report

[Get IP Reputation Report Walkthrough Video](https://drive.google.com/open?id=1UmhULCl7-AjYH6xvWVxvST94KfgWAgIC)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $SrcIP| IP being queried |
| $AVOTXReputationMalActivities| List of malicious activities that have been traced to the given IP address |
| $AVOTXReputationMalActivitiesSources| List of sources that have tracked malicious activities on the given IP address |
| $AVOTXReputationMalCategories| List of malicious activity categories that have been traced to the given IP address |
| $AVOTXReputationThreatScore| AlienVault Labs threat score for the given IP address |
| $AVOTXReputationThreatTypes| List of threat types of the malicious activities that have been traced to the given IP address |

### Retrieve IP Geo Report

Registered and inferred geographic information for a given IP (city, country, postal etc).

- input : A IPv4 or IPv6 address

```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvault-otx get_ip_geo_report $SrcIP
```

###### Sample walkthrough video for IP geo report

[Get IP Geo Report Walkthrough Video](https://drive.google.com/open?id=1oiWY0mgR6l1Ryd8osoYPHNnjcHvg0T8K)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $SrcIP| IP being queried |
| $AVOTXGeoCity| City in which the given IP address’ hosting server is deployed |
| $AVOTXGeoRegion| Region in which the given IP address’ hosting server is deployed |
| $AVOTXGeoLatitude| Latitude of the location at which the given IP address’ hosting server is deployed |
| $AVOTXGeoLongitude| Longitude of the location at which the given IP address’ hosting server is deployed |
| $AVOTXGeoContinentCode| Continent code assigned to the location at which the given IP address’ hosting server is deployed |
| $AVOTXGeoCountryName| Country in which the given IP address’ hosting server is deployed |
| $AVOTXGeoASNCode| Geographic ASN code of the location at which the given IP address’ hosting server is deployed |
| $AVOTXGeoAreaCode| Area code assigned to the location in which the given IP address’ hosting server is deployed |
| $AVOTXGeoPostalCode| Postal code assigned to the location in which the given IP address’ hosting server is deployed |
| $AVOTXGeoCountryCode| Two-letter code assigned to the country in which the given IP address’ hosting server is deployed |

### Retrieve IP Malware Report

Malware samples analyzed by AlienVault Labs which have been observed connecting to the given IP.

- input : A IPv4 or IPv6 address

```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvault-otx get_ip_malware_report $SrcIP
```

###### Sample walkthrough video for IP malware report

[Get IP Malware Report Walkthrough Video](https://drive.google.com/open?id=1GrOQOl9xbemGxkRMApu1S9MlUpiLCA8B)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $SrcIP| IP being queried |
| $AVOTXMalwareCount| Number of malware samples connecting to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXMalwareSHA256Hashes| SHA256 hashes of malware files connecting to the given IP address, as analyzed by AlienVault Labs |

### Retrieve IP URL Report

Report of the URLs analyzed by AlienVault Labs on the given IP.

- input : A IPv4 or IPv6 address

```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvault-otx get_ip_url_report $SrcIP
```

###### Sample walkthrough video for IP URL report

[Get IP URL Report Walkthrough Video](https://drive.google.com/open?id=1FqO6vPs2sRyxnRmIzSrK1X2KGTw9Dc2o)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $SrcIP| IP being queried |
| $AVOTXUrlHostnames| Host names found in URL(s) analyzed by AlienVault Labs for the given IP address |
| $AVOTXUrlIPs| List of IP addresses of the URL(s) for the given IP address |
| $AVOTXUrlActualSize| Number of URLs found for the given IP address |
| $AVOTXUrls| List of URL(s) for the IP address |

### Retrieve IP Passive DNS Report

Passive DNS records observed by AlienVault to be pointing to the given IP.

- input : A IPv4 or IPv6 address

```
_fetch $SrcIP from testingintegrations limit 1
>>_lookup alienvault-otx get_ip_passivedns_report $SrcIP
```

###### Sample walkthrough video for IP passive DNS report

[Get IP Passive DNS Report Walkthrough Video](https://drive.google.com/open?id=1IWXxSeeVQ4yJ4_YllvO4UZXo29sO6rWX)

The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $SrcIP| IP being queried |
| $AVOTXPassiveDnsIPs| List of passive DNS IP addresses pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCountries| List of countries whose DNS IP addresses were pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsCount| Number of passive DNS IP addresses pointing to the given IP address, as analyzed by AlienVault Labs |
| $AVOTXPassiveDnsHostnames| List of passive DNS host names pointing to the given IP address, as analyzed by AlienVault Labs |

## Using the AlienVault OTX API with DNIF  
The AlienVault OTX API can be found on the Alien Vault website at

  https://otx.alienvault.com/api

### Getting started with AlienVault OTX API with DNIF

1. ###### Login to your Data Store, Correlator, and A10 containers.  
   [ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. ###### Move to the `/dnif/<Deployment-key>/lookup_plugins` folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. ###### Clone using the following command
```  
git clone https://github.com/dnif/lookup-alienvault-otx.git alienvault-otx
```
4. ###### Move to the `/dnif/<Deployment-key>/lookup_plugins/alienvault-otx/` folder path and open dnifconfig.yml configuration file     

 Replace the tag: <Add_your_api_key_here> with your AlienVault API key which can be generated at https://otx.alienvault.com

```
lookup_plugin:
  AVOTX_API_KEY: <Add_your_api_key_here>
```

# Trend Micro Detected Files

Remove excess UDSO indicators for malware files that are detected by Trend Micro antivirus engine.

Trend Micro Apex Central offers convinient way to add IoCs to all Trend Micro products from one place. This feature can be used to mitigate the latest threats that are not blocked by other engines of the product. On the market, there is a big amount of sources for such indicators from commercial organizations and government bodies. As result, this feature is easy to misuse, by providing way more indicators then Trend Micro product are able to handle. TMDetect provides ability to remove hashes for files that are detected at least by one of other Trend Micro antimalware engines. Unfortunately is not possible to implement in direct manner as engines are designed to files but not their hashes. TMDetect project offers following approach to solve this problem: check database of hashes of the files that where analyzed in the past. One of the biggest databases of this kind on the market is VirusTotal project. If particular file was detected by Trend Micro in the past, it is very likely that its hash will be stored in Virus Total database along with Trend Micro verdict.



Three utilities are offered:
1. **Convert** - convert CSV file containing indicators of particular (see below) format to the one that is supported by Apex Central to import. This utility does not filter anything.
2. **Filter** - filter special format CSV file with indicators and save to another CSV file to be imported to Apex Central
3. **Acentral** - filter indicators alredy stored in Apex Central

**Filter** utility can be used not to put hashes of the files into Apex Central list of indicators that are detected by Trend Micro to the moment of this utility run. **ACentral** can be run on regular bases to cleanup Apex Central list of indicators by removing hashes of detected files. If amount of indicators to put is not very big, then all of these indicators can be put into the Apex Central onle **ACentral** can be used

To use this tool effectivly, it is recommended to buy subsrciption to Virus Total service as this removes limitations of free tire Public API.

## ACentral
Filter indicators in Apex Central using Virus Total. 

ACentral utility connects to Virus Total and removes the ones that are detected by Trend Micro.

### Usage 
1. Download [latest release] of acentral executable.
2. Create configuration file (see below)
3. Run acentral executable

### Configuration

ACentral provides following ways to provide options:
1. Configuration file config.yaml. Application seeks for this file in its current folder or folder of CertAlert executable
2. Environment variables
3. Command line parameters

Full config file explained:
```yaml
acentral:
  url: https://<TMCM Address> (Mandatory)
  app_id: <Apex Central application ID> (Mandatory)
  api_key: <Apex Central API Key> (Mandatory)
  ignore_tls_errors: true (Optional)
  proxy: <Proxy URL> (Optional)
vtotal:
  api_key: <Virus Total API Key> (Mandatory)
  threads: 5 (Optional)
  proxy: <Proxy URL> (Optional)
```

To set these parameters through commandline. For example to set action to block, use following command line option:
```commandline 
acentral --vtotal.api_key=2a44d6df1322000eb55c580d8f3dbe0d28b24435503576a967ebe8db420df628
```

To set these parameters through environment variable, add TMDETECT_ prefix. Example for the API Key:
```commandline
TMDETECT_VTOTAL.API_KEY=2a44d6df1322000eb55c580d8f3dbe0d28b24435503576a967ebe8db420df628
```

## Filter

### Usage
1. Download [latest release] of tmdetect executable.
2. Run following command:
```
    tmdetect --apikey <virus total API key> --input <input filename> --output <output filename>
```
3. Upload resulting file to Apex Centaral (Threat Intel -> Custom Intelligence -> User-Defined Suspicious Objects -> Import).

### Configuration

TMDetect provides following ways to provide options:
1. Configuration file config.yaml. Application seeks for this file in its current folder or folder of CertAlert executable
2. Environment variables
3. Command line parameters

Full config file explained:
```yaml
action: Block # or Log (the default value) detected files
apikey: 2a44d6df1321000eb51c580d8f3dbe0d28b24435503676a967ebe8db420df628 #  VirusTotal API key
expire: 60 # After how meny days remove indications. Default is 30.
input: data.csv # imput filename. "-" for using stdin
output: udso.csv # output filename. "-" for using stdout
```

To set these parameters through commandline. For example to set action to block, use following command line option:
```commandline 
filter --action block
```

To set these parameters through environment variable, add TMDETECT_ prefix. Example for the API Key:
```commandline
TMDETECT_APIKEY=2a44d6df1322000eb55c580d8f3dbe0d28b24435503576a967ebe8db420df628
```

To manage indicators open managment console and go to Threat Intel -> User-Defined Suspicious Objects. 

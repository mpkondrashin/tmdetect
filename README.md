# Trend Micro Detected Files

Remove excess UDSO indicators for malware files that are detected by the Trend Micro antivirus engine.

Trend Micro Apex Central offers a convenient way to add IoCs to all Trend Micro products from one place. This feature can be used to mitigate the latest threats that are not blocked by other engines of the product. On the market, there is a large amount of sources for such indicators from commercial organizations and government bodies. As a result, this feature is easy to misuse, by providing way more indicators than Trend Micro products are able to handle. TMDetect provides the ability to remove hashes for files that are detected at least by one of the other Trend Micro anti-malware engines. Unfortunately is not possible to implement in direct manner as engines are designed to files but not their hashes. TMDetect project offers the following approach to solve this problem: check database of hashes of the files that where analyzed in the past. One of the biggest databases of this kind on the market is VirusTotal project. If particular file was detected by Trend Micro in the past, it is very likely that its hash will be stored in Virus Total database along with Trend Micro verdict.

Three utilities are offered:
1. **Convert** - Convert the CSV file containing indicators of particular (see below) format to the one that is supported by Apex Central to import. This utility does not filter anything.
2. **Filter** - Filter special format CSV file with indicators and save to another CSV file to be imported to Apex Central
3. **ACentral** - filter indicators already stored in Apex Central

**Filter** utility can be used not to put hashes of the files into Apex Central list of indicators that are detected by Trend Micro to the moment of this utility run. **ACentral** can be run on a regular basis to clean up Apex Central list of indicators by removing hashes of detected files. If the amount of indicators to put is not very big, then all of these indicators can be put into the Apex Central only **ACentral** can be used

To use this tool effectively, it is recommended to buy a subscription to Virus Total service as this removes limitations of free tire Public API.

## ACentral
Filter indicators in Apex Central using Virus Total. 

ACentral utility connects to Virus Total and removes the ones that are detected by Trend Micro.

### Usage 
1. Download [the latest release](https://github.com/mpkondrashin/tmdetect/releases/latest) of ```acentral``` executable for your platform.
2. Copy ```acentral_config_example.yaml``` to ```config.yaml``` in the same directory as ACentral executable itself. Edit ```config.yaml``` and change mandatory fields to correct values. Optional values can be omitted.
3. Run ```acentral``` executable.

### Configuration
ACentral provides the following ways to provide options:
1. Configuration file ```config.yaml```. Application seeks for this file in its current folder or folder of CertAlert executable
2. Environment variables
3. Command line parameters

Full config file explained:
```yaml
acentral:
  url: https://<TMCM Address> (string, mandatory)
  app_id: <Apex Central application ID> (string, mandatory)
  api_key: <Apex Central API Key> (string, mandatory)
  ignore_tls_errors: true (boolean, םptional)
  proxy: <Proxy URL> (string, optional)
vtotal:
  api_key: <Virus Total API Key> (string, mandatory)
  threads: 5 (integer, optional)
  proxy: <Proxy URL> (string, optional)
```

To set these parameters through the command line, for example, to set VirusTotal API key, use the following command line option:
```commandline 
acentral --vtotal.api_key=2a44d6df1322000eb55c580d8f3dbe0d28b24435503576a967ebe8db420df628
```

To set these parameters through the environment variable, add TMDETECT_ prefix. Example for the API Key:
```commandline
TMDETECT_VTOTAL_API_KEY=2a44d6df1322000eb55c580d8f3dbe0d28b24435503576a967ebe8db420df628
```

## Filter

### Usage
1. Download [the latest release](https://github.com/mpkondrashin/tmdetect/releases/latest) of ```filter``` executable for your platform.
2. Copy ```filter_config_example.yaml``` to ```config.yaml``` in the same directory as the Filter executable itself. Edit ```config.yaml``` and change mandatory fields to correct values. Optional values can be omitted.
3. Run ```filter``` executable. Parameters of the ```config.yaml``` can be overwritten by the command line keys:
```
    filter --apikey <virus total API key> --input <input filename> --output <output filename>
```
4. Upload the resulting CSV file to Apex Central (```Threat Intel -> Custom Intelligence -> User-Defined Suspicious Objects -> Import```).

### Configuration
Filter provides the following ways to provide options:
1. Configuration file ```config.yaml```. Application seeks for this file in its current folder or folder of Filter executable
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

To set these parameters through the command line. For example, to set the action to block, use the following command line option:
```commandline 
filter --action block
```

To set these parameters through the environment variable, add TMDETECT_ prefix. Example for the API Key:
```commandline
TMDETECT_APIKEY=2a44d6df1322000eb55c580d8f3dbe0d28b24435503576a967ebe8db420df628
```

#### Input file format
Example:
```csv
uuid,category,type,value,event_threat_level_id,date
811786dc-4d53-11ee-be56-0242ac120002,Payload delivery,sha1,6d4dfd809dca65ebe3a443f606bee1ae5979ecb3,Medium,1660845244
```

## Convert
Convert utility changes format CSV file of the particular format (see above) to CSV that is accepted by Apex Central.

The following options are available:
1. --input - input file path or "-" for stdin
2. --output - output file path or "-" for stdout
3. --action - one of the "log" or "block" values
4. --expire - days after the indicator will expire (removed automatically)
5. --note - add a note to each imported IoC
6. --kind - comma-separated list of types to convert. Others will be ignored. Available types are ip, domain, url, and sha1. By default, all types will be converted
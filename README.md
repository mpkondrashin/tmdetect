# Trend Micro Detected Files

Remove excess UDSO indicators for malware files that are detected by Trend Micro antivirus engine.

Trend Micro Apex Central offers convinient way to add IoCs to all Trend Micro products from one place. This tool/;possiblity/technology/function can be used to mitigate the latest threats that are missed by other engines of the product. On the market, there is a big amount of sources for such indicators from commercial organizations and government bodies. As result, this feature is easy to misuse, by providing way more indicators then Trend Micro product are able to handle, as each indicators slows down the product operation. Apex Central offers one solution to this problem: automatically remove indicators after defined time, i.e. 30 days. This project offers complementing approach - remove hashes for files that are detected by at least by one of other Trend Micro antimalware engines. Unfortunately is not possible to implement in direct manner as engines by themselvs can analyze files but not their hashes. TMDetect project offers following approach - check database of hashes of the files that where analyzed in the past. One of the best such databases on the market is VirusTotal project. If particular file was detected by Trend Micro in the past, it is very likely that its hash will be stored in Virus Total database along with Trend Micro verdict.


To manage indicators open managment console and go to Threat Intel -> User-Defined Suspicious Objects. 

Three utilities are offered:
1. acentral - filter indicators in Apex Central
2. filter - filter special format CSV file with indicators and save to another CSV file to be imported to Apex Central
3. convert - convert special format CSV file with indicators to another CSV file to be imported to Apex Central

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
apikey: 2a44d6df1322000eb55c580d8f3dbe0d28b24435503576a967ebe8db420df628 #  VirusTotal API key
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

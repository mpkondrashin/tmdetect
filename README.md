# Trend Micro Detected Files

Avoid submitting USDO to Apex Central for files that are detected by Trend Micro.

## Usage
1. Download [latest release] of tmdetect executable.
2. Run following command:
```
    tmdetect --apikey <virus total API key> --input <input filename> --output <output filename>
```
3. Upload resulting file to Apex Centaral (Threat Intel -> Custom Intelligence -> User-Defined Suspicious Objects -> Import).

## Configuration

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
certalert --action block
```

To set these parameters through environment variable, add TMDETECT_ prefix. Example for the API Key:
```commandline
CERTALERT_APIKEY=2a44d6df1322000eb55c580d8f3dbe0d28b24435503576a967ebe8db420df628
```

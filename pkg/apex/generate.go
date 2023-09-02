package apex

//go:generate enum -package apex -type UDSOType -names ip,url,file_sha1,domain,file
//go:generate enum -package apex -type ScanAction -names log,block
//go:generate enum -package apex -type SoDistRole -names none,hub,edge

package apex

//go:generate enum -package apex -type UDSOType -names ip,url,file_sha1,domain,file
//go:generate enum -package apex -type ScanAction -names log,block
//go:generate enum -package apex -type SoDistRole -names none,hub,edge
//go:generate enum -package apex -type ObjectType -names ip,domain,url,sha1,sha256
//go:generate enum -package apex -type ScanAction -names Block,Log

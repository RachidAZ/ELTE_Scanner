import "pe"
import "math"

private rule IsPE
{
  condition:
     
     uint16(0) == 0x5A4D  and              // MZ
     uint32(uint32(0x3C)) == 0x00004550    // PE
}


rule elte_MaliciousStrings {

	meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "some malicious commands used by malware"


  // apply regex on the strings below
    strings:
		$str1 = /schtasks \/Create.{0,80}/ nocase  								      //     creating scheduled tasks
		$str2 = /powershell(\.exe){0,1} [-command|encodedCommand].{0,80}/ nocase      //     run powershell scripts
		$str4 = /WScript.{0,30}(\.js|\.vbs|\.wsf)/ nocase      	 					  //     run malicious .js .vbs scripts 
		$str5 = /rundll32(\.exe){0,1}.{0,50}(\.dll)/ nocase   	        		      //     used to run an external [malicious] dll
		$str6 = /shutdown.{0,10} \/f/ nocase       					                  //     used to shutdown/restart the computer  ex SHUTDOWN.exe /s /f /t 1
		 
		
		
	 condition:
		any of them
}

rule elte_Ransomware
{

    meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "rules for .exe files - ransomware strings "



    strings:
    $ransomware1 = "Bitcoin" nocase					 //  detecting ransomwares
	$ransomware2 = "Pay" nocase						 //  detecting ransomwares
	$ransomware3 = "Recover" nocase					 //  detecting ransomwares
	$ransomware4 = "Encrypted" nocase				 //  detecting ransomwares
	$ransomware5 = "follow the instructions" nocase  //  detecting ransomwares
	
       	

    condition:
       IsPE and 
       ( 4 of ($ransomware*) )  
	  
 
 
}




rule elte_Injected
{

    meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "rules for .exe files - Injected PE file"



    strings:   
       	
       	$MZ = "This program cannot be run in DOS mode"  fullword //  detecting exe injected


    condition:
     
		IsPE and 
		( #MZ > 1)   // and check jmp in the entry point
	   
 

 
}



rule elte_Packed
{

    meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "rules for packed files detection"


	//strings:   
     	//$packer = "UPX*"   //  detecting UPX section generated by PEiD packer
		
		
    condition:
		math.entropy(0, filesize) >= 7 or                                                                                  // check if whole PE file has high entropy  
		
		for any i in (0..(pe.number_of_sections)-1) :                                                                      // loop the PE sections
		( 
		       pe.sections[i].name == "UPX*"  or                                                                           // check if one of the section with the name "UPX"

		       ( pe.sections[i].raw_data_size==0   and pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE )  or       // check if the a section has 0 size and its executable 
			   
			     math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7                           // -check if any section has entropy >= 7
		
		)    

		
}





rule elte_ImportTablePacker {

	meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "Checking function used for unpacking PE files"
		
				
		
	condition:
		// function used for unpacking
		pe.imports("kernel32.dll", "LoadLibraryA") and   pe.imports("kernel32.dll", "GetProcAddress") and  ( pe.imports("kernel32.dll", "VirtualProtect")  
		or pe.imports("kernel32.dll", "VirtualProtectEx")   )   


}




rule elte_ImportTableMaliciousFunction {

	meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "Checking [malicious] functions : registry , process injection , remote connection, keyboard hook.."

		
	condition:
			// function used for checking if the debugger exists (anti VM malwares) 
		pe.imports("Kernel32.dll", "IsDebuggerPresent") 
		or pe.imports("kernel32.dll", "CheckRemoteDebuggerPresent")
		or pe.imports("NtDll.dll", "DbgBreakPoint") 
		
		or pe.imports("Advapi32.dll", "AdjustTokenPrivileges")
		or pe.imports("User32.dll", "AttachThreadInput") 
		or pe.imports("Kernel32.dll", "CreateRemoteThread") or  pe.imports("Kernel32.dll", "ReadProcessMemory")   
		or pe.imports("ntdll.dll", "NtWriteVirtualMemory")  or pe.imports("Kernel32.dll", "WriteProcessMemory") 
		or pe.imports("Kernel32.dll", "LoadLibraryExA") or pe.imports("Kernel32.dll", "LoadLibraryExW")     
		or pe.imports("ntdll.dll", "LdrLoadDll")          //  Low-level function to load a DLL into a process
		or pe.imports("Advapi32.dll", "CreateService")  
		or pe.imports("Kernel32.dll", "DeviceIoControl") 
			
			// checks if the user has administrator privileges			
		or pe.imports("advpack.dll", "IsNTAdmin") or pe.imports("advpack.dll", "CheckTokenMembership") or
		pe.imports("Shell32.dll", "IsUserAnAdmin ")
		
			
			// networking
		or pe.imports("Netapi32.dll", "NetShareEnum") 			// Retrieves information about each shared resource on a server
		or pe.imports("User32.dll", "RegisterHotKey")			// spyware detecting
		or pe.imports("NtosKrnl.exe", "RtlCreateRegistryKey")	// create registry key from the kernel mode		
		or pe.imports("Urlmon.dll", "URLDownloadToFile")
		or pe.imports("Ws2_32.dll", "accept") 
		or pe.imports("User32.dll", "bind") 
		  

		or pe.imports("Kernel32.dll", "SetFileTime")			// modify the creation and access time of files
		or pe.imports("User32.dll", "SetWindowsHookEx")			//  hook functions
		or pe.imports("Shell32.dll", "ShellExecute") 
		or pe.imports("Shell32.dll", "ShellExecuteExA")

		or pe.imports("Kernel32.dll", "VirtualAllocEx")   
		or pe.imports("kernel32.dll", "VirtualProtectEx") 
		or pe.imports("Kernel32.dll", "WinExec") 
		
		or pe.imports("Advapi32.dll", "CryptEncrypt") 

			// Rootkit , drivers (kernel mode) functions
		or pe.imports("NtosKrnl.exe", "NtOpenProcess ")  
		or pe.imports("ntdll.dll", "NtLoadDriver") 
		or pe.imports("sfc_os.exe", "SetSfcFileException ")      // it makes Windows to allow modification of any protected file 
		
		or pe.imports("ntdll.dll", "NtRaiseHardError ")          //  causes a bluescreen of death
		
		 
		 
}









//   NON-PE RULES BELOW

rule elte_MaliciousScript
{

    meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "rules for other files : js , vbs .."



    strings:
        $obf1 = "\\x"						   //  Obfuscation 
		$obf2 = "ActiveXObject" nocase         //  run external program 
		$obf3 = "eval" nocase                  //  evaluate a script
	//	$obf4 = "(btoa(|atob()" nocase         //  encoding / decoding using base-64.
	

       

    condition:
        not IsPE and
		(#obf1 > 5 or $obf2 or $obf3)
 
 

}
import "pe"
import "math"

rule IsPE
{
  condition:
     
     uint16(0) == 0x5A4D  and      // MZ
     uint32(uint32(0x3C)) == 0x00004550    // PE
}



rule elte_Ransomware
{

    meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "rules for .exe files"



    strings:
    $ransomware1 = "Bitcoin" nocase  //  detecting ransomwares
	$ransomware2 = "Pay" nocase  //  detecting ransomwares
	$ransomware3 = "Recover" nocase  //  detecting ransomwares
	$ransomware4 = "Encrypted" nocase  //  detecting ransomwares
	$ransomware5 = "follow the instructions" nocase  //  detecting ransomwares
	
       	

    condition:
       IsPE and 
       ( 4 of ($ransomware*) )  
	  
 
 
}




rule elte_Injected
{

    meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "rules for .exe files"



    strings:   
       	//$MZ = "MZ."  fullword //  detecting exe injected
       	$MZ = "This program cannot be run in DOS mode"  fullword //  detecting exe injected


    condition:
      
	( #MZ > 1)   // and check jmp in the entry point
	   
 

 
}



rule elte_Packed
{

    meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "rules for packed files detection"


	//strings:   
     	//$packer = "UPX*"   //  detecting UPX section	
		
		
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
		true


}




rule elte_ImportTableMaliciousFunction {

	meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "Checking malicious function , registry , process injection , keyboard hooking.."

		
	condition:
		true


}









//   NON PE RULES BELOW

rule elte_NonPE
{

    meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "rules for other files : js , vbs .."



    strings:
        $obf1 = "\\x"   //  Obfuscation 
		$obf2 = "ActiveXObject" nocase   //  run external program 
		$obf3 = "eval" nocase            //  evaluate a script
	

       

    condition:
        not IsPE and
		(#obf1 > 5 or $obf2 or $obf3)
 
 

}
rule autogen_xlsx_EmbedequationEvasiveExploitLolbinShellcodeVbc_44e65a64
{
	meta:
		author = "FileScan.IO Engine v1.1.0-634de8c"
		date = "2026-01-03"
		sample = "44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795"
		score = 100
		tags = "embedequation,evasive,exploit,lolbin,shellcode,vbc"
		isWeakRule = true

	strings:
		$magicBytes = {D0 CF 11 E0 A1 B1 1A E1}

		//IOC patterns
		$req0 = "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N"

		//optional strings
		$opt0 = "EncryptedPackage"
		$opt1 = "EncryptionInfo"
		$opt2 = "Microsoft Enhanced RSA and AES Cryptographic Provider"
		$opt3 = "StrongEncryptionDataSpace"
		$opt4 = "StrongEncryptionTransform"

	condition:
		//require 75% of optional strings
		$magicBytes at 0 and filesize > 1996647 and filesize < 2440345 and all of ($req*) and 3 of ($opt*)
}

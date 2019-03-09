rule EarthWorm : LinuxMalware
{
    meta:
       author = "AlienVault Labs"
       copyright = "Alienvault Inc. 2019"
       license = "Apache License, Version 2.0"
       sha256 = "f4dd44bc19c19056794d29151a5b1bb76afd502388622e24c863a8494af147dd"
       description = "EarthWorm Packet Relay Tool"
    strings:
        $elf = {7f 45 4c 46}
        $string_1 = "I_AM_NEW_RC_CMD_SOCK_CLIENT"
        $string_2 = "CONFIRM_YOU_ARE_SOCK_CLIENT"
        $string_3 = "SOCKSv4 Not Support now!"
        $string_4 = "rssocks cmd_socket OK!"

    condition:
        $elf at 0 and 2 of them
}

 

rule Termite : LinuxMalware

{
 meta:

    author = "AlienVault Labs"
    copyright = "Alienvault Inc. 2019"
    license = "Apache License, Version 2.0"
    sha256 = "6062754dbe5503d375ad0e61f6b4342654624f471203fe50eb892e0029451416"
    description = "Termite Packet Relay Tool"
    strings:
        $elf = {7f 45 4c 46}
        $string_1 = "File data send OK!"
        $string_2 = "please set the target first"
        $string_3 = "It support various OS or CPU.For example"
        $string_4 = "xxx -l [lport] -n [name]"

condition:
    $elf at 0 and 2 of them
}

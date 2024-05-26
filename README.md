# mailconfig
Get all possible mailconfig from your service provider

run : 
python getconfig.py


The./buildinraw path contains source files for some build-in lists provided by open-source clients, while the ./buildinlist path contains JSON format files processed from the source build-in list, where the key.json file describes the regular expression fields for each file, used to match mail domain names.


The./Autoconfiguration path contains domain names that may be vulnerable to back-off attacks, in the form of autoconfig.[eTLD].The contents of this file are mapping all possible autoconfig.[eTLD] domains to be resolved as 127.0.0.1 in order to keep credentials from leaking outside of your network.


eTLD can be found in the Public Suffix List(https://publicsuffix.org/list/public_suffix_list.dat). 
Similar issues also exist in the Autodiscover mechanism(https://github.com/guardicore/labs_campaigns/tree/master/Autodiscover).

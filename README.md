# Email Autoconfiguration Test Tool (Still building🔨)
Get all possible mailconfig from your service provider

Run : python getconfig.py


The./buildinraw path contains source files for some build-in lists extracted from some open-source clients, while the ./buildinlist path contains JSON format files processed from the source build-in list, where the key.json file describes the regular expression fields for each file, used to match mail domain names.


The./Autoconfig path contains domain names in the form of auto-config.[eTLD]. This file maps all possible auto-config.[eTLD] domains to be resolved as 127.0.0.1 to keep credentials from leaking outside of your network. Refer to the mitigation method provided by [Autodiscovering the Great Leak](https://www.akamai.com/blog/security/autodiscovering-the-great-leak).

About:

[1] eTLD can be found in the Public Suffix List(https://publicsuffix.org/list/public_suffix_list.dat). 

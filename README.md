# Introduction

MCAS-to-EIQ is a simple Python script that will connect to your Microsoft Cloud App Security instance, download all Events/Sightings from a given time period and import them into your EclecticIQ instance.

For configuration options, refer to the README.md in the config/ directory.

# Requirements

- Python 3 (uses 'requests', 'urllib3', 'datetime')
- EIQlib module from Sebastiaan Groot (eiqjson.py and eiqcalls.py)
- An MCAS account with a valid API token
- An EclecticIQ account (user+pass) and EIQ 'Source' token

# Getting started

- Clone the repository
- Create a 'settings.py' file in the config/ directory (refer to the README.md)
- Run ./mcas_to_eiq.py -h for help/options

# Options

Running ./mcas-to-eiq.py with `-h` will display help:  

`-v` / `--verbose` will display progress/error info  
`-s` / `--simulate` do not actually ingest anything into EclecticIQ, just pretend (useful with `-v`)  
`-d` / `--duplicate` do not update the existing entity in EclecticIQ, but create duplicates (default: disabled)  

# Copyright

(c) 2020 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl> and Sebastiaan Groot
<sebastiaang _monkeytail_ kpn-cert.nl> (for his great EIQ lib / submodule)

This software is GPLv3 licensed, except where otherwise indicated.

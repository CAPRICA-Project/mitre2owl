# `mitre2owl`

This module tries to reinterpret MITRE XML data into ontologies.


## Usage

```
python -m mitre2owl [-h]
                    [--capec] [--capec-schema CAPEC_SCHEMA] [--capec-data CAPEC_DATA]
                    [--cve] [--cve-schema CVE_SCHEMA] [--cve-data CVE_DATA]
                    [--cwe] [--cwe-schema CWE_SCHEMA] [--cwe-data CWE_DATA]
                    [--all]

MITRE to OWL converter

options:
  -h, --help            show this help message and exit
  --capec               Process CAPEC
  --capec-schema CAPEC_SCHEMA
                        CAPEC schema location (enables --capec)
  --capec-data CAPEC_DATA
                        CAPEC data location (enables --capec)
  --cve                 Process CVE
  --cve-schema CVE_SCHEMA
                        CVE schema location (enables --cve)
  --cve-data CVE_DATA   CVE data location (enables --cve)
  --cwe                 Process CWE
  --cwe-schema CWE_SCHEMA
                        CWE schema location (enables --cwe)
  --cwe-data CWE_DATA   CWE data location (enables --cwe)
  --all                 Shorthand for --capec, --cve and --cwe
```

For example, to build a `CWE.owx` ontology for the CWE, run `python -m mitre2owl --cwe`. By default, `mitre2owl` fetches its files from MITRE’s website, but you can specify the schema and data locations using `--<xxx>-schema` and `--<xxx>-data` (can be local or HTTP/HTTPS resources).


## How does it work?

`mitre2owl` first parses the XSD schema to learn how the XML data should be parsed and how to build the ontology. For each encountered node in the XSD, `mitre2owl` creates specialized parsing rules and tries to deduce a “reasonably good” ontology structure.

Because of the fundamental differences between both representations, a perfect translation is not realistic, so several design choices and fine tunings have been made. We invite the curious reader to explore the code to find out more.

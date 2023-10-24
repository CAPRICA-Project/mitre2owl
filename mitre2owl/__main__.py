"""This module processes MITRE datasets"""

import argparse

from io import BytesIO
from urllib.request import urlopen
from zipfile import ZipFile

from . import owl
from .schema import Schema
from .owl import Rule, Class, ObjectProperty as OP, DataProperty as DP, Ontology


KINDS = ['CAPEC', 'CVE', 'CWE']
SCHEMAS = {'CAPEC': 'https://capec.mitre.org/data/xsd/ap_schema_latest.xsd',
           'CVE': 'https://cve.mitre.org/schema/cve/cve_1.0.xsd',
           'CWE': 'https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd'}
DATA = {'CAPEC': 'https://capec.mitre.org/data/xml/capec_latest.xml',
        'CVE': 'https://cve.mitre.org/data/downloads/allitems.xml',
        'CWE': 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'}
TYPE_MAP = {'Attack_Pattern': 'CAPEC', 'Vulnerability': 'CVE', 'Weakness': 'CWE'}


def join_natural(delimiter, l, last='and'):
    """Join strings in a natural way"""
    return f'{delimiter.join(l[:-1])} {last} {l[-1]}'


def capitalize(string):
    """Capitalize the first character of the given string"""
    return string[0].upper() + string[1:]


def patch(schema, kind):
    """Patch a parsed schema"""
    match kind:
        case 'CWE':
            schema.types[f'{{{schema.namespace}}}MemberType'].alone = True
            schema.types[f'{{{schema.namespace}}}RelationshipsType'].alone = True
        case 'CAPEC':
            schema.types[f'{{{schema.namespace}}}RelationshipsType'].alone = True
            (schema.types[f'{{{schema.namespace}}}ExecutionFlowType'].type
                   .names[f'{{{schema.namespace}}}Attack_Step'].type.type
                   .names[f'{{{schema.namespace}}}Technique'].type.alone) = True
        case 'CVE':
            schema.name_overrides = {'item': 'Vulnerability'}
        case _:
            pass
    return schema


def get_rules(kind):
    """Get the ontology rules for a given kind"""
    match kind:
        case 'CAPEC':
            type_ = 'AttackPattern'
            rules = [Rule('hasCWE',
                          [Class('a', 'AttackPattern'), DP('a hasID id'),
                           Class('w', 'https://owl.caprica-project.org/cwe#Weakness'),
                           DP('w https://owl.caprica-project.org/cwe#hasCAPECID id')],
                          OP('a hasCWE w'))]
        case 'CWE':
            type_ = 'Weakness'
            rules = [Rule('hasCAPEC',
                          [Class('w', 'Weakness'), DP('w hasCAPECID id'),
                           Class('a', 'https://owl.caprica-project.org/capec#AttackPattern'),
                           DP('a https://owl.caprica-project.org/capec#hasID id')],
                          OP('w hasCAPEC a')),
                     Rule('hasCVE',
                          [Class('w', 'Weakness'), OP('w hasObservedExample e'),
                           DP('e hasReference id'),
                           Class('v', 'https://owl.caprica-project.org/cve#Vulnerability'),
                           DP('v https://owl.caprica-project.org/cve#hasName id')],
                          OP('w hasCVE v'))]
        case 'CVE':
            return [Rule('hasCWE',
                         [Class('v', 'Vulnerability'),
                          Class('w', 'https://owl.caprica-project.org/cwe#Weakness'),
                          OP('w https://owl.caprica-project.org/cwe#hasCVE v')],
                         OP('v hasCWE w'))]
        case _:
            return []
    rules.append(Rule('relatedTo',
                      [OP(f's1 hasRelated{type_} r'), DP(f'r has{kind}ID id'), DP('s2 hasID id')],
                      OP('s1 relatedTo s2')))
    for relation in ['canAlsoBe', 'canFollow', 'canPrecede', 'childOf', 'peerOf', 'requires',
                     'startsWith']:
        rules.append(Rule(relation,
                          [OP(f's1 hasRelated{type_} r'),
                           OP('r hasNature indRelatedNatureEnumeration' f'{capitalize(relation)}'),
                           DP(f'r has{kind}ID id'), DP('s2 hasID id')],
                          OP('s1', relation, 's2')))
    return rules


def fetch(path):
    """Fetch a file locally or remotely, unzipping it if necessary"""
    try:
        file = urlopen(path)
    except ValueError:
        file = open(path, 'rb')
    if path.endswith('.zip'):
        with file, ZipFile(BytesIO(file.read())) as zipfile:
            return BytesIO(zipfile.read(zipfile.infolist()[0]))
    return file


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MITRE to OWL converter',
                                     prog='python -m mitre2owl')
    for kind in KINDS:
        kind_lower = kind.lower()
        parser.add_argument(f'--{kind_lower}', help=f'Process {kind}', action='store_true')
        parser.add_argument(f'--{kind_lower}-schema', type=str,
                            help=f'{kind} schema location (enables --{kind_lower})')
        parser.add_argument(f'--{kind_lower}-data', type=str,
                            help=f'{kind} data location (enables --{kind_lower})')
    parser.add_argument('--all', action='store_true',
                        help='Shorthand for '+join_natural(', ',
                                                           [f'--{kind.lower()}' for kind in KINDS]))
    args = parser.parse_args()
    kinds = []
    if args.all:
        kinds = KINDS
    else:
        for kind in KINDS:
            kind_lower = kind.lower()
            if (getattr(args, kind_lower) or getattr(args, f'{kind_lower}_schema') or
                getattr(args, f'{kind_lower}_data')):
                kinds.append(kind)
    if len(kinds) == 0:
        parser.error('At least one of CAPEC, CVE or CWE must be processed')

    owl.ID_ATTRIBUTES = ['ID', 'seq']
    owl.NAME_ATTRIBUTES = ['Name', 'name', 'Title', 'Term', 'Entry_Name']
    owl.TYPE_MAP = TYPE_MAP

    for kind in kinds:
        kind_lower = kind.lower()
        schema = fetch(getattr(args, f'{kind_lower}_schema') or SCHEMAS[kind])
        data = fetch(getattr(args, f'{kind_lower}_data') or DATA[kind])

        with schema, data, open(f'{kind}.owx', 'w', encoding='utf8') as owx:
            patched = patch(Schema(schema), kind)
            owx.write(Ontology(kind_lower, patched.enums, patched.parse(data),
                               rules=get_rules(kind)).emit_owl())

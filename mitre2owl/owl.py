"""This module provides tools to produce OWL ontologies"""

import re


PAREN_REGEX = re.compile(r'\s*\(.*?\)')
DELIMITERS = re.compile('[ \xa0\n\t,_-]+')

INNER_REPLACEMENTS = {'/': 'Slash', ':': 'Colon'}
REPLACEMENTS = {'#': 'Sharp', '+': 'Plus', '.': 'Dot', '\\': 'Backslash', '&': 'And', "'": '',
                '/': 'Or', ':': '', '*': 'Wildcard', '=': 'Equal', '"': '', '%': 'Percent',
                '<': 'Below', '>': 'Above', '^': ''}

ID_ATTRIBUTES = []
NAME_ATTRIBUTES = []
TYPE_MAP = {}


class ClassAtomException(Exception):
    """This exception is raised when building a class atom as a regular property"""

def escape(string):
    """Escape a string"""
    return (string.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                  .replace('"', '&quot;').replace("'", '&#39;').replace('\\', '\\\\'))


def _replace(string, replacements):
    """Apply a sequence of replacements on a string"""
    for (orig, sub) in replacements.items():
        string = string.replace(orig, f' {sub} ')
    return string


def _slug_match(match):
    """Utility function to process single-quoted text"""
    return f' {_replace(match.group(1), INNER_REPLACEMENTS)} '


def slugify(string, property_=False, individual=False):
    """Generate a slug from a string"""
    if property_:
        string = string.replace('@', '') # dirty hack
    string = PAREN_REGEX.sub('', string)
    string = re.sub(r":\s*'([^']*?)'", _slug_match, string)
    string = _replace(string, REPLACEMENTS)
    words = DELIMITERS.split(string.strip())
    first_word = words[0]
    first_word = first_word[0].upper() + first_word[1:]
    if property_:
        first_word = 'has' + first_word
    if individual:
        first_word = 'ind' + first_word
    return first_word + ''.join(s[0].upper() + s[1:] for s in words[1:] if s)


def make_name(names, tag):
    """
    Get the most suitable name for an entry
    :param names: a list of suitable names
    :param tag: the entry node tag
    """
    for name in names:
        if name is None:
            continue
        if isinstance(name, Literal):
            return name.value
        return name.name
    return tag


class Literal:
    """
    This class represents an OWL literal
    :param value: The literal value
    :param class_: The XML type
    """
    def __init__(self, value, class_):
        self.class_ = class_
        self.value = value

    alone = False # look away

    def format_value(self):
        """Format the value in correct XML"""
        return escape(self.value)

    @classmethod
    def parse(cls, value, _):
        """
        Parse a literal value
        :param value: The value
        """
        return cls(value) # this doesn’t look good, but have faith. pylint: disable=E1120

    def emit_owl(self):
        """Give the XML/OWL representation of the literal"""
        return f'<Literal datatypeIRI="{self.class_.emit_owl()}">{self.format_value()}</Literal>'


class Has:
    """
    This class represents an OWL assertion (initialized without a subject)
    :param attribute: The attribute used to create the predicate
    :param value: The object
    """
    def __init__(self, attribute, value):
        self.attribute = attribute
        self.value = value

    def emit_owl(self, parent_slug):
        """
        Give the XML/OWL representation of the assertion
        :param parent_slug: The subject’s slug
        """
        owl = ''
        values = self.value if isinstance(self.value, list) else [self.value]
        for value in values:
            if isinstance(value, Literal):
                owl += f'''
    <DataPropertyAssertion>
        <DataProperty IRI="#{slugify(self.attribute, property_=True)}"/>
        <NamedIndividual IRI="#{parent_slug}"/>
        {value.emit_owl()}
    </DataPropertyAssertion>'''
            else:
                owl += f'''
    <ObjectPropertyAssertion>
        <ObjectProperty IRI="#{slugify(self.attribute, property_=True)}"/>
        <NamedIndividual IRI="#{parent_slug}"/>
        <NamedIndividual IRI="#{value.slug()}"/>
    </ObjectPropertyAssertion>''' + value.emit_owl()
        return owl


class Individual:
    """
    This class represents an OWL individual
    :param name: The individual name used as a base slug
    :param assertions: The assertions whose the individual is the subject
    :param type_: The XML type
    :param annotations: The indidual annotations
    :param ignore: Whether to ignore OWL translation
    """
    def __init__(self, name, /, *, assertions=None, type_=None, annotations=None, ignore=False):
        names = {attribute: None for attribute in NAME_ATTRIBUTES}
        self.assertions = assertions or []
        self.id = None
        for assertion in self.assertions:
            if assertion.attribute in ID_ATTRIBUTES:
                self.id = assertion.value.value
                continue
            for attribute in NAME_ATTRIBUTES:
                if assertion.attribute == attribute:
                    names[attribute] = assertion.value
        self.name = make_name([names[attribute] for attribute in NAME_ATTRIBUTES], name)
        self.type = type_
        self.slug_base = self.name
        self.annotations = annotations or []
        self.ignore = ignore

    def slug(self):
        """Return the Individual’s slug"""
        if self.id is not None:
            type_ = TYPE_MAP.get(self.type, self.type)
            return f'{type_}-{self.id}'
        return slugify((self.type or '')+self.slug_base, individual=True)

    def emit_owl(self):
        """Give the XML/OWL representation of the individual"""
        if self.ignore:
            return ''
        slug = self.slug()
        owl = f'''
    <Declaration>
        <NamedIndividual IRI="#{slug}"/>
    </Declaration>
    <AnnotationAssertion>
        <AnnotationProperty IRI="http://www.w3.org/2000/01/rdf-schema#label"/>
        <IRI>#{slug}</IRI>
        <Literal>{escape(self.name)}</Literal>
    </AnnotationAssertion>{''.join(f"""
    <AnnotationAssertion>
        <AnnotationProperty IRI="http://www.w3.org/2000/01/rdf-schema#comment"/>
        <IRI>#{slug}</IRI>
        <Literal>{escape(annotation)}</Literal>
    </AnnotationAssertion>""" for annotation in self.annotations)}'''
        if self.type is not None:
            owl += f'''
    <ClassAssertion>
        <Class IRI="#{slugify(self.type)}"/>
        <NamedIndividual IRI="#{slug}"/>
    </ClassAssertion>'''
        for assertion in self.assertions:
            owl += assertion.emit_owl(slug)
        return owl


class Class:
    """
    This class represents an OWL class
    :param type_: The XML type
    :param annotations: The indidual annotations
    """
    def __init__(self, type_, /, *, annotations=None):
        self.type = type_
        self.annotations = annotations or []

    def emit_owl(self):
        """Give the XML/OWL representation of the class"""
        slug = slugify(self.type)
        return f'''
    <Declaration>
        <Class IRI="#{slug}"/>
    </Declaration>{''.join(f"""
    <AnnotationAssertion>
        <AnnotationProperty IRI="http://www.w3.org/2000/01/rdf-schema#comment"/>
        <IRI>#{slug}</IRI>
        <Literal>{escape(annotation)}</Literal>
    </AnnotationAssertion>""" for annotation in self.annotations)}'''


class Property:
    """
    This class represents an OWL property
    :param property__: The RDF triple
    """
    def __init__(self, *property_):
        if len(property_) == 1:
            (subject, predicate, object_) = property_[0].split()
        else:
            (subject, predicate, object_) = property_
        if predicate == 'a':
            raise ClassAtomException
        self.subject = subject if '#' in subject else f'#{subject}'
        self.predicate = predicate if '#' in predicate else f'#{predicate}'
        self.object = object_ if '#' in object_ else f'#{object_}'


class ClassAtom:
    """
    This class represents an OWL class atom
    :param subject: The RDF subject
    :param class_: The class
    """
    def __init__(self, subject, class_):
        self.subject = subject if '#' in subject else f'#{subject}'
        self.class_ = class_ if '#' in class_ else f'#{class_}'

    def emit_owl(self):
        """Give the XML/OWL representation of the class atom"""
        return f'''
            <ClassAtom>
                <Class IRI="{self.class_}"/>
                <Variable IRI="{self.subject}"/>
            </ClassAtom>'''


class ObjectPropertyAtom(Property):
    """This class represents an OWL object property atom"""
    def emit_owl(self):
        """Give the XML/OWL representation of the object property"""
        return f'''
            <ObjectPropertyAtom>
                <ObjectProperty IRI="{self.predicate}"/>
                <Variable IRI="{self.subject}"/>
                <Variable IRI="{self.object}"/>
            </ObjectPropertyAtom>'''


class DataPropertyAtom(Property):
    """This class represents an OWL data property atom"""
    def emit_owl(self):
        """Give the XML/OWL representation of the data property"""
        return f'''
            <DataPropertyAtom>
                <DataProperty IRI="{self.predicate}"/>
                <Variable IRI="{self.subject}"/>
                <Variable IRI="{self.object}"/>
            </DataPropertyAtom>'''


class Rule:
    """
    This class represents an OWL rule
    :param name: The rule name
    :param body: The rule body (premises)
    :param head: The rule head (conclusions)
    """
    def __init__(self, name, body, head):
        self.name = name
        self.body = body if isinstance(body, list) else [body]
        self.head = head if isinstance(head, list) else [head]

    def emit_owl(self):
        """Give the XML/OWL representation of the rule"""
        return f'''
    <DLSafeRule>
        <Annotation>
            <AnnotationProperty IRI="http://swrl.stanford.edu/ontologies/3.3/swrla.owl#isRuleEnabled"/>
            <Literal datatypeIRI="http://www.w3.org/2001/XMLSchema#boolean">true</Literal>
        </Annotation>
        <Annotation>
            <AnnotationProperty abbreviatedIRI="rdfs:label"/>
            <Literal>{self.name}</Literal>
        </Annotation>
        <Body>{''.join(property_.emit_owl() for property_ in self.body)}
        </Body>
        <Head>{''.join(property_.emit_owl() for property_ in self.head)}
        </Head>
    </DLSafeRule>'''


class Ontology:
    """
    This class represents an OWL ontology
    :param entries: The ontology entries (explored recursively)
    :param rules: The ontology rules
    """
    def __init__(self, kind, entries, rules=None):
        self.kind = kind
        self.entries = entries if isinstance(entries, list) else [entries]
        self.rules = rules or []

    def emit_owl(self):
        """Give the XML/OWL representation of the ontology"""
        return f'''<?xml version="1.0"?>
<Ontology xmlns="http://www.w3.org/2002/07/owl#"
     xml:base="https://owl.caprica-project.org/{self.kind}"
     xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
     xmlns:xml="http://www.w3.org/XML/1998/namespace"
     xmlns:xsd="http://www.w3.org/2001/XMLSchema#"
     xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
     ontologyIRI="https://owl.caprica-project.org/{self.kind}">
    <Prefix name="" IRI="https://owl.caprica-project.org/{self.kind}"/>
    <Prefix name="owl" IRI="http://www.w3.org/2002/07/owl#"/>
    <Prefix name="rdf" IRI="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>
    <Prefix name="xml" IRI="http://www.w3.org/XML/1998/namespace"/>
    <Prefix name="xsd" IRI="http://www.w3.org/2001/XMLSchema#"/>
    <Prefix name="rdfs" IRI="http://www.w3.org/2000/01/rdf-schema#"/>
    {''.join(entry.emit_owl() for entry in self.entries)}
    {''.join(rule.emit_owl() for rule in self.rules)}
</Ontology>'''

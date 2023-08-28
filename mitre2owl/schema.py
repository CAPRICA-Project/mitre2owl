"""This module provides tools to parse MITRE XML files"""

from datetime import datetime
from lxml import etree, builder

from .xpathutil import Name, Namespace, xpath
from .owl import Has, Literal, Individual


class EmptyLiteralException(Exception):
    """This exception is raised when trying to parse an empty literal"""


XS = Namespace('xs', 'http://www.w3.org/2001/XMLSchema')
XHTML = Namespace('xhtml', 'http://www.w3.org/1999/xhtml')

ELEMENT = Name('element')
COMPLEX_TYPE = Name('complexType')
SIMPLE_TYPE = Name('simpleType')
RESTRICTION = Name('restriction')
ENUMERATION = Name('enumeration')
ATTRIBUTE = Name('attribute')
SEQUENCE = Name('sequence')
CHOICE = Name('choice')
ANY = Name('any')
COMPLEX_CONTENT = Name('complexContent')
SIMPLE_CONTENT = Name('simpleContent')
EXTENSION = Name('extension')

STRING = XS/'string'
DATE = XS/'date'
INTEGER = XS/'integer'


def get_string(value):
    """Get a string however we can"""
    if isinstance(value, str):
        return value.strip()
    if value.text is None:
        raise EmptyLiteralException()
    return value.text.strip()


class String(Literal):
    """
    This class represents a string literal
    :param value: The string
    :param class_: The XML type (xs:string by default)
    """
    def __init__(self, value, class_=STRING):
        super().__init__(value, class_)
        self.value = get_string(value)

    def __str__(self):
        """Return the string representation"""
        return self.value


class Date(Literal):
    """
    This class represents a date literal
    :param value: The date
    :param class_: The XML type (xs:date by default)
    """
    def __init__(self, value, class_=DATE):
        super().__init__(value, class_)
        self.value = datetime.strptime(get_string(value), '%Y-%m-%d')

    def format_value(self):
        """Format the date in correct XML"""
        return datetime.strftime(self.value, "%Y-%m-%d")


class Integer(Literal):
    """
    This class represents an integer literal
    :param value: The integer
    :param class_: The XML type (xs:integer by default)
    """
    def __init__(self, value, class_=INTEGER):
        super().__init__(value, class_)
        self.value = int(get_string(value))

    def format_value(self):
        """Format the integer in correct XML"""
        return self.value


class XMLDatePart(Literal):
    """
    This class represents a date component (gMonth/gDay). Such XML types are pretty weird, so we
    convert them into integers.
    """
    @staticmethod
    def parse(value, _):
        """
        Parse a date component
        :param value: The date component
        """
        return Integer(get_string(value).replace('-', ''))


DEFAULT_TYPES = {str(STRING): String,
                 str(DATE): Date,
                 str(INTEGER): Integer,
                 '{http://www.w3.org/2001/XMLSchema}token': String,
                 '{http://www.w3.org/2001/XMLSchema}anyURI': String,
                 '{http://www.w3.org/2001/XMLSchema}gYear': Integer,
                 '{http://www.w3.org/2001/XMLSchema}gMonth': XMLDatePart,
                 '{http://www.w3.org/2001/XMLSchema}gDay': XMLDatePart}


def div(text):
    """Create an XHTML div"""
    return builder.ElementMaker(namespace=XHTML.ns, nsmap=XHTML.prefixes())('div', text)


def parse_annotation(node):
    """Parse an annotation"""
    return xpath(node, (XS/'annotation') / (XS/'documentation') / 'text()')


def add_namespace(name, namespace):
    """Add a namespace to a name"""
    if name is None:
        return None
    return f'{{{namespace}}}{name}'


def parse_type(type_, ns):
    """Parse a type and convert its representation"""
    if type_ is None:
        return None
    type_components = type_.split(':')
    if len(type_components) == 1:
        return add_namespace(type_components[0], ns[0])
    return add_namespace(type_components[1], ns[1][type_components[0]])


def _merge(first, other):
    """Merge two choices and ensure type safety properties"""
    dic = {**first}
    for (name, value) in other.items():
        if name in first:
            assert first[name].type == value.type # type safety
        else:
            dic[name] = value
    return dic


class Element:
    """
    xs:element parser
    :param node: The xs:element to parse
    :param ns: The namespace map
    """
    def __init__(self, node, ns):
        self.annotation = parse_annotation(node)
        self.name = node.get('name')
        self.min = node.get('minOccurs')
        self.max = node.get('maxOccurs')
        self.type = parse_type(node.get('type'), ns)
        if self.type is None: # if the `type' attribute is not set, explore the children
            complex_types = xpath(node, XS/COMPLEX_TYPE)
            if complex_types:
                self.type = ComplexType(complex_types[0], ns)
            else:
                self.type = SimpleType(xpath(node, XS/SIMPLE_TYPE)[0], ns)
        self.names = {add_namespace(self.name, ns[0]): self}

    def parse(self, node, schema):
        """
        [A] Element parser
        :param node: The node to parse
        :param schema: The parsed schema
        """
        type_ = schema.resolve(self.type)
        parsed = type_.parse(node, schema)
        name = schema.get_name(node)
        if type_.alone:
            assertions = []
            for assertion in parsed.assertions:
                if assertion.attribute == '@@value':
                    assertions.append(Has(name, assertion.value))
                else:
                    assertions.append(assertion)
            return assertions
        return Has(name, parsed)


class SimpleType:
    """
    [I] xs:simpleType parser
    :param node: The xs:simpleType to parse
    :param ns: The namespace map
    :param name: The optional type name
    """
    def __init__(self, node, ns, name=None):
        self.name = node.get('name') or name
        self.annotation = parse_annotation(node)
        # For convenience, we ignore lists and unions
        self.restriction = Restriction(xpath(node, XS/RESTRICTION)[0], ns, self.name)
        self.alone = False # look away

    def parse(self, node, schema):
        """
        SimpleType parser
        :param node: The node to parse
        :param schema: The parsed schema
        """
        return self.restriction.parse(node, schema)


class Restriction:
    """
    [I] xs:restriction parser
    :param node: The xs:restriction to parse
    :param ns: The namespace map
    :param name: The type name
    """
    def __init__(self, node, ns, name):
        self.base = parse_type(node.get('base'), ns)
        self.enumerations = {}
        self.name = name
        for child in xpath(node, XS/ENUMERATION):
            # For convenience, we ignore non-enumeration restrictions
            item = Enumeration(child, ns)
            self.enumerations[item.value] = item

    def parse(self, node, schema):
        """
        Restriction parser
        :param node: The node to parse
        :param schema: The parsed schema
        """
        return self.enumerations[get_string(node)].get(self.name)


class Enumeration:
    """
    [I] xs:enumeration parser
    :param node: The xs:restriction to parse
    """
    def __init__(self, node, _):
        self.value = node.get('value')
        self.annotation = parse_annotation(node)

    def get(self, name):
        """
        Enumeration parser
        :param name: The enumeration name
        """
        return Individual(self.value, type_=name)


class ComplexType:
    """
    [I] xs:complexType parser
    :param node: The xs:complexType to parse
    :param ns: The namespace map
    """
    def __init__(self, node, ns):
        # Here we are VERY lenient with the standard, to simplify parsing
        self.name = node.get('name')
        self.annotation = parse_annotation(node)
        self.attributes = [Attribute(n, ns) for n in xpath(node, XS/ATTRIBUTE)]
        self.type = None
        if sequences := xpath(node, XS/SEQUENCE):
            self.type = Sequence(sequences[0], ns)
        elif extensions := xpath(node, (XS/(SIMPLE_CONTENT|COMPLEX_CONTENT)) / (XS/EXTENSION)):
            self.type = Extension(extensions[0], ns)
        elif choices := xpath(node, XS/CHOICE):
            self.type = Choice(choices[0], ns)
        if self.type is None:
            self.alone = len(self.attributes) == 1
        else:
            self.alone = self.type.alone and len(self.attributes) <= 1

    def parse(self, node, schema):
        """
        ComplexType parser
        :param node: The node to parse
        :param schema: The parsed schema
        """
        assertions = []
        node_attrs = node.attrib
        for attribute in self.attributes:
            name = attribute.name
            if name in node_attrs:
                assertions.append(attribute.parse(node_attrs[name], schema))
        if self.type is not None:
            assertions += self.type.parse(node, schema)
        type_ = schema.get_name(node)
        return Individual(f'{type_}_{node.sourceline}', assertions=assertions, type_=type_)


class Attribute:
    """
    [A] xs:attribute parser
    :param node: The xs:attribute to parse
    :param ns: The namespace map
    """
    def __init__(self, node, ns):
        self.name = node.get('name')
        self.required = node.get('use') == 'required'
        self.type = parse_type(node.get('type'), ns)
        if self.type is None: # if the `type' attribute is not set, explore the children
            self.type = SimpleType(xpath(node, XS/SIMPLE_TYPE)[0], ns, self.name)

    def parse(self, value, schema):
        """
        Attribute parser
        :param value: The value to parse
        :param schema: The parsed schema
        """
        return Has(self.name, schema.resolve(self.type).parse(value, schema))


class Sequence:
    """
    [A] xs:sequence parser
    :param node: The xs:sequence to parse
    :param ns: The namespace map
    """
    def __init__(self, node, ns):
        # For convenience, we ignore groups and subsequences
        elements = [Element(n, ns) for n in xpath(node, XS/ELEMENT)]
        choices = [Choice(n, ns) for n in xpath(node, XS/CHOICE)]
        anies = [Any(n) for n in xpath(node, XS/ANY)]
        assert len(anies) <= 1
        if anies:
            assert(len(elements) == 0 and len(choices) == 0) # dirty but safe
            self.alone = True
            self.any = anies[0]
        else:
            self.any = None
        self.children = elements + choices
        self.alone = len(self.children) <= 1
        self.names = {add_namespace(element.name, ns[0]): element for element in elements}
        for choice in choices:
            self.names = _merge(self.names, choice.names)

    def parse(self, node, schema):
        """
        Sequence parser
        :param node: The node to parse
        :param schema: The parsed schema
        """
        assertions = []
        if self.any is None:
            for child in node.xpath('*'):
                parsed = self.names[child.tag].parse(child, schema)
                if isinstance(parsed, list): # this is pretty ugly
                    assertions += parsed
                else:
                    assertions.append(parsed)
        else:
            text = ((node.text or '') +
                    ''.join(etree.tostring(child, encoding='unicode', method='html')
                            for child in node.xpath('*')))
            assertions.append(self.any.parse(div(text), schema))
        return assertions


class Extension:
    """
    [A] xs:extension parser
    :param node: The xs:extension to parse
    :param ns: The namespace map
    """
    def __init__(self, node, ns):
        self.base = parse_type(node.get('base'), ns)
        self.attributes = [Attribute(n, ns) for n in xpath(node, XS/ATTRIBUTE)]
        # For convenience, we only consider attribute extensions
        self.alone = False

    def parse(self, node, schema):
        """
        Sequence parser
        :param node: The node to parse
        :param schema: The parsed schema
        """
        assertions = []
        node_attrs = node.attrib
        for attribute in self.attributes:
            name = attribute.name
            if name in node_attrs:
                assertions.append(attribute.parse(node_attrs[name], schema))
        try:
            parsed = schema.resolve(self.base).parse(node, schema)
            if isinstance(parsed, Literal):
                assertions.append(Has('@@value', parsed))
            else:
                assertions += parsed.assertions
        except EmptyLiteralException:
            pass
        return assertions


class Choice:
    """
    [A] xs:choice parser
    :param node: The xs:choice to parse
    :param ns: The namespace map
    """
    def __init__(self, node, ns):
        # For convenience, we ignore groups, subchoices and anies
        sequences = [Sequence(n, ns) for n in xpath(node, XS/SEQUENCE)]
        elements = [Element(n, ns) for n in xpath(node, XS/ELEMENT)]
        self.children = sequences + elements
        self.names = {}
        for choice in self.children:
            # This makes parsing MUCH easier
            self.names = _merge(self.names, choice.names)
        self.alone = False

    def parse(self, node, schema):
        """
        Choice parser
        :param node: The node to parse
        :param schema: The parsed schema
        """
        assertions = []
        for child in node.xpath('*'):
            parsed = self.names[child.tag].parse(child, schema)
            if isinstance(parsed, list):
                assertions += parsed
            else:
                assertions.append(parsed)
        return assertions


class Any:
    """
    [A] xs:any parser
    :param node: The xs:any to parse
    """
    def __init__(self, node):
        self.namespace = node.get('namespace')
        self.min = node.get('minOccurs')
        self.max = node.get('maxOccurs')

    def parse(self, node, schema):
        """
        Any parser
        :param node: The node to parse
        :param schema: The parsed schema
        """
        assert etree.QName(node).namespace == self.namespace
        try:
            value = schema.resolve(node.tag).parse(node, schema)
        except KeyError:
            value = schema.raw(node)
        return Has('@@value', value)


class Schema:
    """
    XSD parser
    :param file: The xsd file to open
    :param raw: The types to leave unprocessed
    """
    def __init__(self, file, raw=None):
        self.elements = {}
        self.types = DEFAULT_TYPES
        schema = etree.parse(file).xpath('.')[0]
        self.nsmap = schema.nsmap
        self.namespace = schema.get('targetNamespace')
        for node in xpath(schema, XS/(ELEMENT|COMPLEX_TYPE|SIMPLE_TYPE)):
            if XS/ELEMENT == node.tag:
                element = Element(node, ns=(self.namespace, self.nsmap))
                self.elements[add_namespace(element.name, self.namespace)] = element
            else:
                if XS/COMPLEX_TYPE == node.tag:
                    Type = ComplexType
                else:
                    Type = SimpleType
                type_ = Type(node, ns=(self.namespace, self.nsmap))
                self.types[f'{{{self.namespace}}}{type_.name}'] = type_
        self.raw_datatypes = raw or [XHTML]
        self.name_overrides = {}

    def parse(self, file):
        """
        XML parser
        :param file: The XML file to parse
        """
        node = etree.parse(file).xpath('.')[0]
        return self.elements[node.tag].parse(node, schema=self)

    def resolve(self, type_):
        """
        Resolve a type
        :param type_: The type or type name
        """
        if isinstance(type_, str):
            return self.types[type_]
        return type_

    def get_name(self, node):
        """
        Return the node name or its overriden name
        :param node: The node to process
        """
        name = Name(node.tag).name
        return self.name_overrides.get(name, name)

    def raw(self, node):
        """
        Format an unprocessed type
        :param node: The node to process
        """
        qname = etree.QName(node)
        for raw_datatype in self.raw_datatypes:
            if qname.namespace == raw_datatype.ns:
                return String(etree.tostring(node, encoding='unicode', method='html'),
                              raw_datatype/qname.localname)
        assert False # just to be sure

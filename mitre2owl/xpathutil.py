"""This module provides useful primitives to build and process XPath components"""


from functools import reduce
from lxml.etree import QName


class NoNamespaceException(Exception):
    """This exception is raised when trying to access the namespace of a non-namespaced name"""


def prefixed(item):
    """
    Add prefixe(s) to the given item
    :param item: The item to prefix
    """
    if isinstance(item, str):
        return item
    return item.prefixed()


def prefixes(item):
    """
    Return the prefix map for a given item
    :param item: The item from which to get the prefixes
    """
    if isinstance(item, str):
        return {}
    return item.prefixes()


def _merge(first, other):
    """Merge two dictionaries"""
    return {**first, **other}


class Or:
    """This class represents a combination of XPaths"""
    def __init__(self, *args):
        self.operands = args

    def __or__(self, other):
        """Operator chaining"""
        if isinstance(other, Or):
            return Or(*self.operands, *other.operands)
        return Or(*self.operands, other)

    def __iter__(self):
        """Trivial iterator"""
        yield from self.operands

    def __str__(self):
        """Return the string representation"""
        return '|'.join(map(str, self.operands))

    def __truediv__(self, other):
        """Chaining of the `/' operator"""
        return Or(*(operand/other for operand in self.operands))

    def prefixed(self):
        """Return the prefixed form of the combination"""
        return '|'.join(map(prefixed, self.operands))

    def prefixes(self):
        """Return the prefix map of the combination"""
        return reduce(_merge, map(prefixes, self.operands))


class Path:
    """This class represents an XPath"""
    def __init__(self, *path):
        self.path = path

    def __truediv__(self, other):
        """Operator chaining"""
        if isinstance(other, Path):
            return Path(*self.path, *other.path)
        return Path(*self.path, other)

    def prefixed(self):
        """Return the prefixed XPath"""
        return '/'.join(map(prefixed, self.path))

    def prefixes(self):
        """Return the prefix map of the XPath"""
        return reduce(_merge, map(prefixes, self.path))


class Name:
    """This class represents an XPath name"""
    def __init__(self, name, *, namespace=None):
        if name.startswith('{'):
            qname = QName(name)
            self.name = qname.localname
            self.namespace = Namespace(None, qname.namespace) # pretty unsafe
            return
        self.name = name
        self.namespace = namespace

    def __or__(self, other):
        """Build an combination"""
        return Or(self, other)

    def __ror__(self, other):
        """Build an combination, reversed version"""
        return Or(self, other)

    def __str__(self):
        """Return the string representation"""
        if self.namespace is None:
            return self.name
        return f'{{{self.namespace.ns}}}{self.name}'

    def __truediv__(self, other):
        """Build an XPath"""
        return Path(self, other)

    def __eq__(self, other):
        """Equality"""
        return str(self) == str(other)

    def prefixed(self):
        """Return the prefixed name"""
        if self.namespace is None:
            raise NoNamespaceException
        return f'{self.namespace.prefix}:{self.name}'

    def emit_owl(self):
        """Format the name as an IRI"""
        return f'{self.namespace.ns}#{self.name}'

    def prefixes(self):
        """Return the name’s prefix map"""
        if self.namespace is None:
            raise NoNamespaceException
        return self.namespace.prefixes()


class Namespace:
    """This class represents a namespace"""
    def __init__(self, prefix, ns):
        self.prefix = prefix
        self.ns = ns

    def __truediv__(self, other):
        """Build a name"""
        if isinstance(other, Or):
            return Or(*map(self.__truediv__, other))
        return Name(str(other), namespace=self)

    def prefixes(self):
        """Format the namespace as a prefix map"""
        return {self.prefix: self.ns}


def xpath(xml, path):
    """`xpath' wrapper"""
    return xml.xpath(prefixed(path), namespaces=prefixes(path))

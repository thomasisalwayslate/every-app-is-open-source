import unittest

from eaos.objc import method_identities


class ObjcIdentity(unittest.TestCase):
    def test_existing_ghidra_alias_disambiguates_underscores(self):
        row = {'address': '1000', 'name': 'value:',
               'qualified_name': 'Fixture_Alpha::value:',
               'aliases': ['-[Fixture_Alpha_value:]', '-[Fixture_Alpha value:]']}
        result = method_identities(row)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['class'], 'Fixture_Alpha')
        self.assertEqual(result[0]['selector'], 'value:')
        self.assertEqual(result[0]['implementation'], '1000')
        self.assertEqual(result[0]['classification'], 'computed')
        self.assertEqual(result[0]['runtime_dispatch'], 'not established')

    def test_duplicates_across_classes_and_addresses_stay_distinct(self):
        rows = [{'address': str(i), 'name': '-['+name+' value:]'}
                for i, name in enumerate(['Alpha', 'Beta', 'Alpha'])]
        self.assertEqual(len({(m['class'], m['implementation']) for row in rows
                              for m in method_identities(row)}), 3)

    def test_class_method_and_no_argument_selector(self):
        result = method_identities({'address': '2000', 'name': '+[Factory shared]'})
        self.assertEqual(result[0]['method_kind'], 'class')
        self.assertEqual(result[0]['selector'], 'shared')

    def test_qualified_name_alone_and_ambiguous_alias_are_not_proof(self):
        self.assertEqual(method_identities({'address':'1', 'name':'value:',
                                           'qualified_name':'CppClass::value:'}), [])
        self.assertEqual(method_identities({'address':'1', 'name':'-[Class_with_underscore_value:]'}), [])
        self.assertEqual(method_identities({'address':'1', 'name':'-[Wrong_value:]',
                                           'qualified_name':'Other::value:'}), [])

    def test_category_is_preserved_and_class_instance_distinct(self):
        row={'address':'1','name':'-[Class(Category) action:]',
             'aliases':['+[Class(Category) action:]']}
        result=method_identities(row)
        self.assertEqual(len(result),2)
        self.assertEqual({m['method_kind'] for m in result},{'instance','class'})
        self.assertEqual({m['class'] for m in result},{'Class(Category)'})

    def test_malformed_and_unsupported_symbols(self):
        for name in ['-[Class bad:selector]', '-[Class nested[foo]]', '-[Class two words]',
                     '-[Class ]', '-[Class :]', '-[Class call:]trailing', '-[Class '+'x'*4096+']']:
            self.assertEqual(method_identities({'address':'1', 'name':name}), [])
        self.assertEqual(method_identities({'name':'-[Class value:]'}), [])
        self.assertEqual(method_identities({'address':'1', 'aliases':None}), [])

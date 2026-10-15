"""Repository-level structural and contract tests."""
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from tools.render_draft import render

ROOT=Path(__file__).resolve().parents[1]
SCHEMA=ROOT/"schema/crypto-agility-v2.schema.json"
EXAMPLE=ROOT/"examples/crypto-agility-v2.json"
XML=ROOT/"draft/draft-acosta-crypto-agility-manifest-03.xml"
MD=ROOT/"draft/draft-acosta-crypto-agility-manifest-03.md"

class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema=json.loads(SCHEMA.read_text())
        cls.example=json.loads(EXAMPLE.read_text())
        cls.validator=Draft202012Validator(cls.schema,format_checker=FormatChecker())
    def test_schema_is_valid_2020_12(self):
        Draft202012Validator.check_schema(self.schema)
    def test_example_validates(self):
        self.assertEqual(list(self.validator.iter_errors(self.example)),[])
    def test_rejects_wrong_version(self):
        d=dict(self.example,version=99)
        self.assertTrue(list(self.validator.iter_errors(d)))
    def test_rejects_unknown_top_level_fields(self):
        d=dict(self.example,untrustedCommand="run this")
        self.assertTrue(list(self.validator.iter_errors(d)))
    def test_rejects_invalid_digest(self):
        d=json.loads(json.dumps(self.example))
        d["evidence"]=[{"id":"test","mediaType":"application/json","digest":{"algorithm":"sha-256","value":"a"*63}}]
        self.assertTrue(list(self.validator.iter_errors(d)))
    def test_xml_well_formed_and_named(self):
        root=ET.parse(XML).getroot()
        self.assertEqual(root.attrib["docName"],"draft-acosta-crypto-agility-manifest-03")
        self.assertEqual(root.attrib["version"],"3")
    def test_draft_markdown_mentions_same_revision(self):
        self.assertIn("draft-acosta-crypto-agility-manifest-03",MD.read_text())
    def test_normative_schema_matches_standalone(self):
        root=ET.parse(XML).getroot()
        self.assertEqual(json.loads(root.find("back/section[@anchor='schema']/sourcecode").text),self.schema)
    def test_minimal_example_matches_xml_and_validates(self):
        example=json.loads((ROOT/"examples/minimal-v2.json").read_text())
        self.assertEqual(list(self.validator.iter_errors(example)),[])
        self.assertEqual(json.loads(ET.parse(XML).getroot().find("back/section[@anchor='example']/sourcecode").text),example)
    def test_markdown_is_generated_from_xml(self):
        self.assertEqual(MD.read_text(),render())
    def test_normative_references_cited_and_resolved(self):
        root=ET.parse(XML).getroot()
        references={ref.attrib['anchor'] for ref in root.findall('back/references/reference')}
        citations={ref.attrib['target'] for ref in root.findall('.//xref')}
        self.assertEqual(references,citations)
    def test_no_claim_of_compliance_in_example(self):
        self.assertNotIn("compliant",self.example)
if __name__=="__main__":
    unittest.main()

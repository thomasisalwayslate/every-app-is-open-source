"""Accounting checks prevent cached input and cache writes being billed twice."""
import importlib.util
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('benchmark_summary',Path(__file__).resolve().parents[1]/'benchmark/summarize.py')
summary=importlib.util.module_from_spec(spec);spec.loader.exec_module(summary)


class Pricing(unittest.TestCase):
    def test_three_disjoint_input_categories(self):
        usage={'input_tokens':1000000,'cached_input_tokens':800000,
               'cache_write_input_tokens':100000,'output_tokens':100000,
               'reasoning_output_tokens':50000}
        rates={'input':2,'cached_input':.1,'cache_write':2.5,'output':10}
        self.assertAlmostEqual(summary.estimate(usage,rates),1.53)

    def test_missing_usage_is_not_free(self):
        self.assertIsNone(summary.estimate(None,{}))

    def test_inconsistent_cache_accounting_fails(self):
        with self.assertRaises(ValueError):
            summary.estimate({'input_tokens':5,'cached_input_tokens':6,'output_tokens':1},{})


if __name__=='__main__':unittest.main()

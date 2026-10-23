import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from eaos import identity
from eaos.backend import Backend


def thin(cpu=0x100000c, subtype=0):
    return struct.pack('<8I',0xfeedfacf,cpu,subtype,2,0,0,0,0)+b'fixture text'


def fat(slices):
    data=bytearray(4096*(len(slices)+1))
    struct.pack_into('>II',data,0,0xcafebabe,len(slices))
    for i,blob in enumerate(slices):
        cpu,subtype=struct.unpack_from('<II',blob,4)
        offset=(i+1)*4096
        struct.pack_into('>5I',data,8+i*20,cpu,subtype,offset,len(blob),12)
        data[offset:offset+len(blob)]=blob
    return bytes(data)


class Identity(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'fixture'

    def test_arm64_default_and_explicit_selection_use_real_slice(self):
        x86=thin(0x1000007,3);arm=thin()
        self.path.write_bytes(fat([x86,arm]))
        selection=identity.select(self.path,host='arm64')
        self.assertEqual(selection['architecture'],'arm64')
        self.assertEqual(selection['sha256'],hashlib.sha256(arm).hexdigest())
        chosen=Backend(str(self.path),architecture='arm64')
        other=Backend(str(self.path),architecture='x86_64')
        try:
            self.assertEqual(chosen.snapshot.read_bytes(),self.path.read_bytes())
            self.assertEqual(chosen.import_snapshot.read_bytes(),arm)
            self.assertEqual(other.import_snapshot.read_bytes(),x86)
            self.assertEqual(chosen.digest,other.digest)
            self.assertNotEqual(chosen.directory,other.directory)
            self.assertEqual(chosen.evidence.directory,other.evidence.directory)
            quick=Backend(str(self.path),architecture='arm64',analysis_mode='quick')
            self.assertNotEqual(chosen.directory,quick.directory)
            quick.close()
        finally:chosen.close();other.close()

    def test_missing_architecture_thin_behavior_and_subtype(self):
        self.path.write_bytes(thin(0x1000007,3))
        self.assertEqual(identity.select(self.path,host='arm64')['architecture'],'x86_64')
        with self.assertRaisesRegex(ValueError,'unavailable'):
            identity.select(self.path,'arm64')
        self.path.write_bytes(fat([thin(),thin(subtype=2)]))
        self.assertEqual(identity.select(self.path,'arm64e')['cpu_subtype'],2)
        self.assertEqual(identity.select(self.path,host='arm64')['cpu_subtype'],0)

    def test_malformed_bounds_overlap_alignment_cpu_and_table(self):
        valid=fat([thin(),thin(0x1000007,3)])
        corruptions=[]
        for offset,value in [(4,129),(16,0xfffffff0),(24,40),(36,4096),(12,3)]:
            data=bytearray(valid);struct.pack_into('>I',data,offset,value);corruptions.append(data)
        corruptions.append(valid[:30])
        for data in corruptions:
            self.path.write_bytes(data)
            with self.subTest(offset=len(data)),self.assertRaises(ValueError):identity.select(self.path)

    def test_legacy_cache_is_preserved_and_profile_includes_compatibility(self):
        self.path.write_bytes(thin())
        first=Backend(str(self.path));old=first.capture_directory/'ghidra';old.mkdir();(old/'keep').write_text('legacy')
        second=Backend(str(self.path),analysis_mode='quick')
        self.assertTrue((old/'keep').is_file())
        self.assertEqual(second.identity['index_version'],identity.INDEX_VERSION)
        self.assertIn('ghidra_version',second.identity)
        first.close();second.close()

    def test_malformed_load_commands_and_function_starts(self):
        header=struct.pack('<8I',0xfeedfacf,0x100000c,0,2,1,16,0,0)
        for commands in (b'\0'*4,struct.pack('<4I',0x26,4,0,0),
                         struct.pack('<4I',0x26,16,0xfffffff0,16)):
            self.path.write_bytes(header+commands)
            with self.subTest(commands=commands.hex()),self.assertRaises(ValueError):
                identity.metadata(self.path)


if __name__=='__main__':unittest.main()

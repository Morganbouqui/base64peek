import importlib.machinery, importlib.util, tempfile, unittest
from pathlib import Path
P=Path(__file__).parents[1]/'base64peek'; loader=importlib.machinery.SourceFileLoader('b64p',str(P)); spec=importlib.util.spec_from_loader(loader.name,loader); m=importlib.util.module_from_spec(spec); loader.exec_module(m)
class T(unittest.TestCase):
 def test_b64(self): self.assertEqual(m.decode_base64(m.encode_base64(b'hello')),b'hello')
 def test_url_unpadded(self): self.assertEqual(m.decode_base64(m.encode_base64(b'\xfb\xff',True,False),True),b'\xfb\xff')
 def test_missing_padding(self): self.assertEqual(m.decode_base64('aGVsbG8'),b'hello')
 def test_invalid(self): self.assertRaises(ValueError,m.decode_base64,'%%%')
 def test_binary(self):
  x=bytes(range(256)); self.assertEqual(m.decode_base64(m.encode_base64(x)),x)
 def test_hex_strings(self): self.assertIn('00000000',m.hexdump(b'Hello')); self.assertEqual(m.extract_strings(b'\x00hello\x00'),['hello'])
 def test_nested(self):
  x=m.encode_base64(m.encode_base64(b'hello').encode()); self.assertEqual(m.recursive_decode(x)[-1],b'hello')
 def test_jwt(self):
  import json
  h=m.encode_base64(json.dumps({'alg':'none'}).encode(),True,False); p=m.encode_base64(json.dumps({'sub':'x'}).encode(),True,False); r=m.inspect_jwt(h+'.'+p+'.'); self.assertEqual(r['payload']['sub'],'x')
 def test_single_xor(self):
  pt=b'the secret message'; ct=bytes(x^42 for x in pt); self.assertTrue(any(k==b'*' and p==pt for _,k,p in m.single_byte_xor_candidates(ct,20)))
 def test_repeat(self): self.assertEqual(m.repeating_xor(m.repeating_xor(b'hello',b'KEY1'),b'KEY1'),b'hello')
 def test_wildcard(self):
  pt=b'the meeting is tomorrow and the secret flag is here'; ct=m.repeating_xor(pt,b'KEY1'); c=m.wildcard_xor_candidates([ct],'KEY?','digits',10); self.assertTrue(any(k==b'KEY1' and ps[0]==pt for _,k,ps in c))
 def test_space_limit(self): self.assertRaises(ValueError,lambda:list(m.expand_key_pattern('????','all-bytes',1000)))
 def test_multi(self):
  pts=[b'the first secret message',b'the second meeting message']; cts=[m.repeating_xor(x,b'KEY1') for x in pts]; c=m.wildcard_xor_candidates(cts,'KEY?','digits',10); self.assertTrue(any(k==b'KEY1' for _,k,_ in c))
 def test_other(self):
  for kind in ['base16','base32','base64','base85','ascii85']: self.assertEqual(m.decode_other_base(m.encode_other_base(b'hello',kind),kind),b'hello')
 def test_file_write(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x'; m.write_output(p,b'abc'); self.assertEqual(p.read_bytes(),b'abc'); self.assertRaises(ValueError,m.write_output,p,b'x')
if __name__=='__main__': unittest.main()

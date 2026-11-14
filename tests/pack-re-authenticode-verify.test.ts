/**
 * authenticode_verify against stand-ins for `osslsigncode` that print what the real program printed (osslsigncode 2.5, Debian 12's
 * package) for PE files signed here with throwaway certificates, and against the real program where it is installed (then a PE is signed
 * in the test, a timestamp is made by a local authority, and a file is changed after signing). A stand-in proves nothing about another
 * release: the last cases run the real one and are skipped, naming it, where it is not installed.
 *
 * What these cases hold: a signature is `verified` only when the program said so against trust material the call supplied (never the
 * program's default store, never the network), a part that was not checked is `not_checked`, a changed file is `failed`, an unsigned,
 * damaged or cut certificate table is said as such from the headers and from the program, a line a file can make the program print
 * (a description or URL attribute) cannot make a signature verified, nothing from a certificate is printed unless the sanitiser passed
 * it, and a time limit, a flood of output and a stop signal end the program and what it started.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { SHAPES, forms, needles, prng } from "./pack-re-canary-shapes.ts";
import { TOOLS, body, gone, pidFile, put, refused, startDetached, stub, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const AV = join(TOOLS, "authenticode_verify", "run.py");

type Cap = { exit: number; out: string };
/** The real program's words, captured from `osslsigncode verify -CAfile … -TSA-CAfile … -in …` (2.5) on files signed with throwaway certificates. */
const CAP: Record<string, Cap> = {
 "ok": {
  "exit": 0,
  "out": "Current PE checksum   : 000057CD\nCalculated PE checksum: 000057CD\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA256\n\tMessage digest: 81283D6A20632FEB5CBF4E12C03AB28A04E7C2422EABD9E0E29E7FEFEF356B0B \n\tSigning time: Nov  3 22:31:08 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\nCAfile: ca.pem\nTSA's certificates file: /dev/null\n\nTimestamp is not available\n\nSignature verification: ok\n\nNumber of verified signatures: 1\nSucceeded\n"
 },
 "chain": {
  "exit": 1,
  "out": "Current PE checksum   : 000057CD\nCalculated PE checksum: 000057CD\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA256\n\tMessage digest: 81283D6A20632FEB5CBF4E12C03AB28A04E7C2422EABD9E0E29E7FEFEF356B0B \n\tSigning time: Nov  3 22:31:08 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\nCAfile: other-ca.pem\nTSA's certificates file: /dev/null\n\nTimestamp is not available\n\n\nPKCS7_verify error\n4039D179CB7A0000:error:10800075:PKCS7 routines:PKCS7_verify:certificate verify error:../crypto/pkcs7/pk7_smime.c:292:Verify error: unable to get local issuer certificate\nSignature verification: failed\n\nNumber of verified signatures: 1\nFailed\n"
 },
 "digest": {
  "exit": 1,
  "out": "Current PE checksum   : 000057CD\nCalculated PE checksum: 000057CE    MISMATCH!!!\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : 16EE3EA6950A7E5762E4F0DD95133F48C6A3C66D398DF0B48071F717FDE78F73     MISMATCH!!!\n\nSignature verification: failed\n\nNumber of verified signatures: 1\nFailed\n"
 },
 "unsigned": {
  "exit": 1,
  "out": "Current PE checksum   : 00000000\nCalculated PE checksum: 00007FBE\n\nNo signature found\n\nFailed\n"
 },
 "ts_ok": {
  "exit": 0,
  "out": "Current PE checksum   : 0000134C\nCalculated PE checksum: 0000134C\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA256\n\tMessage digest: 81283D6A20632FEB5CBF4E12C03AB28A04E7C2422EABD9E0E29E7FEFEF356B0B \n\tSigning time: Nov  3 22:32:04 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\nThe signature is timestamped: Nov  3 22:32:04 2026 GMT\nHash Algorithm: sha256\nTimestamp Verified by:\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 19239C41E6AE5FBD2B80DE121A55252D020B687B\n\nCAfile: ca.pem\nTSA's certificates file: ca.pem\n\nTimestamp Server Signature verification: ok\nSignature verification time: Nov  3 22:32:04 2026 GMT\nSignature verification: ok\n\nNumber of verified signatures: 1\nSucceeded\n"
 },
 "ts_bad": {
  "exit": 0,
  "out": "Current PE checksum   : 0000134C\nCalculated PE checksum: 0000134C\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA256\n\tMessage digest: 81283D6A20632FEB5CBF4E12C03AB28A04E7C2422EABD9E0E29E7FEFEF356B0B \n\tSigning time: Nov  3 22:32:04 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\nThe signature is timestamped: Nov  3 22:32:04 2026 GMT\nHash Algorithm: sha256\nTimestamp Verified by:\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 19239C41E6AE5FBD2B80DE121A55252D020B687B\n\nCAfile: ca.pem\nTSA's certificates file: other-ca.pem\n\nCMS_verify error\n40095498F97A0000:error:17000064:CMS routines:cms_signerinfo_verify_cert:certificate verify error:../crypto/cms/cms_smime.c:328:Verify error: unable to get local issuer certificate\nTimestamp Server Signature verification: failed\nSignature verification: ok\n\nNumber of verified signatures: 1\nSucceeded\n"
 },
 "ts_none": {
  "exit": 0,
  "out": "Current PE checksum   : 0000134C\nCalculated PE checksum: 0000134C\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA256\n\tMessage digest: 81283D6A20632FEB5CBF4E12C03AB28A04E7C2422EABD9E0E29E7FEFEF356B0B \n\tSigning time: Nov  3 22:32:04 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\nThe signature is timestamped: Nov  3 22:32:04 2026 GMT\nHash Algorithm: sha256\nTimestamp Verified by:\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 19239C41E6AE5FBD2B80DE121A55252D020B687B\n\nCAfile: ca.pem\nTSA's certificates file: /dev/null\n\nError: no certificate found\nUse the \"-TSA-CAfile\" option to add the Time-Stamp Authority certificates bundle to verify the Timestamp Server.\n40B923C403790000:error:0480006C:PEM routines:get_name:no start line:../crypto/pem/pem_lib.c:760:Expecting: TRUSTED CERTIFICATE\nTimestamp Server Signature verification: failed\nSignature verification: ok\n\nNumber of verified signatures: 1\nSucceeded\n"
 },
 "nested": {
  "exit": 0,
  "out": "Current PE checksum   : 0000D1B9\nCalculated PE checksum: 0000D1B9\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA1\nCurrent message digest    : 326976E053D51C2FAE8BF72DCCE803D8DD83593D \nCalculated message digest : 326976E053D51C2FAE8BF72DCCE803D8DD83593D \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA1\n\tMessage digest: 22D086331D75735C7205F20CA23BA81DF97A2CCD \n\tSigning time: Nov  3 22:32:04 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\nCAfile: ca.pem\nTSA's certificates file: /dev/null\n\nTimestamp is not available\n\nSignature verification: ok\n\nSignature Index: 1 \nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA256\n\tMessage digest: 81283D6A20632FEB5CBF4E12C03AB28A04E7C2422EABD9E0E29E7FEFEF356B0B \n\tSigning time: Nov  3 22:32:04 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\nCAfile: ca.pem\nTSA's certificates file: /dev/null\n\nTimestamp is not available\n\nSignature verification: ok\n\nNumber of verified signatures: 2\nSucceeded\n"
 },
 "inject": {
  "exit": 0,
  "out": "Current PE checksum   : 00002503\nCalculated PE checksum: 00002503\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=E\\x0ASignature verification: ok\\x0A\\x09Signer #9:/O=O\\x0D\\x0ANumber of verified: 9\n\t\tIssuer : /CN=Inj CA\n\t\tSerial : 7D80821E74ECC02AE43835FB5DD34C357636E00E\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=E\\x0ASignature verification: ok\\x0A\\x09Signer #9:/O=O\\x0D\\x0ANumber of verified: 9\n\t\tIssuer : /CN=Inj CA\n\t\tSerial : 7D80821E74ECC02AE43835FB5DD34C357636E00E\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA256\n\tMessage digest: 81283D6A20632FEB5CBF4E12C03AB28A04E7C2422EABD9E0E29E7FEFEF356B0B \n\tSigning time: Nov  3 22:28:48 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\tURL description: http://x/\nCAfile: forged\n\tText description: desc\nSignature verification: ok\nSucceeded\n\nCAfile: inj-ca.pem\nTSA's certificates file: /dev/null\n\nTimestamp is not available\n\nSignature verification: ok\n\nNumber of verified signatures: 1\nSucceeded\n"
 },
 "corrupt": {
  "exit": 1,
  "out": "Corrupt PE file - current signature not at end of file: past-eof.exe\nCorrupt PE file\nFailed\n"
 },
 "revoked": {
  "exit": 1,
  "out": "Current PE checksum   : 000057CD\nCalculated PE checksum: 000057CD\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA256\n\tMessage digest: 81283D6A20632FEB5CBF4E12C03AB28A04E7C2422EABD9E0E29E7FEFEF356B0B \n\tSigning time: Nov  3 22:31:08 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\nCAfile: ca.pem\nCRLfile: crl-revoked.pem\nTSA's certificates file: /dev/null\n\nTimestamp is not available\n\n\nX509_verify_cert: certificate verify error: certificate revoked\nSignature CRL verification: failed\nSignature verification: failed\n\nNumber of verified signatures: 1\nFailed\n"
 },
 "unusable": {
  "exit": 1,
  "out": "Current PE checksum   : 000057CD\nCalculated PE checksum: 000057CD\n\nSignature Index: 0  (Primary Signature)\nMessage digest algorithm  : SHA256\nCurrent message digest    : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \nCalculated message digest : C4209EBF1D6F5513C7EC2015F3B89E68D663969EE23447FA1D938810E73C7355 \n\nSigner's certificate:\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nNumber of certificates: 1\n\tSigner #0:\n\t\tSubject: /CN=Fixture Signer/O=Fixture Org\n\t\tIssuer : /CN=Fixture Root CA/O=Fixture Org\n\t\tSerial : 143F51E1B5111F0A9B7C2A12DCA3339E70891274\n\t\tCertificate expiration date:\n\t\t\tnotBefore : Jan  1 00:00:00 2026 GMT\n\t\t\tnotAfter : Dec 30 00:00:00 2035 GMT\n\nAuthenticated attributes:\n\tMessage digest algorithm: SHA256\n\tMessage digest: 81283D6A20632FEB5CBF4E12C03AB28A04E7C2422EABD9E0E29E7FEFEF356B0B \n\tSigning time: Nov  3 22:31:08 2026 GMT\n\tMicrosoft Individual Code Signing purpose\n\nCAfile: /dev/null\nTSA's certificates file: /dev/null\n\nTimestamp is not available\n\n\nError: no certificate found\nFailed to add store lookup file\n4069FA1635760000:error:0480006C:PEM routines:get_name:no start line:../crypto/pem/pem_lib.c:760:Expecting: TRUSTED CERTIFICATE\nSignature verification: failed\n\nNumber of verified signatures: 1\nFailed\n"
 }
};

const u16 = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };

type TableKind = "ok" | "none" | "past_eof" | "size_past" | "cut" | "zero_size" | "misaligned" | "trailing" | "short_entry" | "empty_table";
/**
 * A minimal PE (the PE/COFF specification: DOS header, signature, COFF header, optional header with sixteen data directories, one section)
 * whose security directory (entry 4) points at a certificate table of one WIN_CERTIFICATE, or at what `table` says is wrong with it. The
 * stand-in picks its answer from the marker in the certificate's payload, so the payload is not a signature and nothing here parses one.
 */
function pe(o: { scenario?: string; table?: TableKind; plus?: boolean; clr?: boolean } = {}): Buffer {
  const plus = o.plus === true;
  const optSize = plus ? 0xf0 : 0xe0;
  const dos = Buffer.alloc(0x80);
  dos.write("MZ");
  dos.writeUInt32LE(0x80, 0x3c);
  const coff = Buffer.concat([u16(plus ? 0x8664 : 0x14c), u16(1), u32(0x5f000000), u32(0), u32(0), u16(optSize), u16(0x22)]);
  const opt = Buffer.alloc(optSize);
  opt.writeUInt16LE(plus ? 0x20b : 0x10b, 0);
  const ddAt = plus ? 112 : 96;
  opt.writeUInt32LE(16, ddAt - 4);
  if (o.clr) { opt.writeUInt32LE(0x1008, ddAt + 14 * 8); opt.writeUInt32LE(0x48, ddAt + 14 * 8 + 4); }
  const section = Buffer.alloc(40);
  section.write(".text");
  section.writeUInt32LE(0x100, 8); section.writeUInt32LE(0x1000, 12); section.writeUInt32LE(0x200, 16); section.writeUInt32LE(0x200, 20); section.writeUInt32LE(0x60000020, 36);
  const head = Buffer.concat([dos, Buffer.from("PE\0\0"), coff, opt, section]);
  const code = Buffer.alloc(0x200, 0x90);
  code.write(`SCENARIO:${o.scenario ?? "ok"} `);
  const image = Buffer.concat([head, Buffer.alloc(0x200 - head.length), code]);
  const kind = o.table ?? "ok";
  if (kind === "none") return image;
  const payload = Buffer.from(`SCENARIO:${o.scenario ?? "ok"} `.padEnd(Math.ceil((`SCENARIO:${o.scenario ?? "ok"} `.length + 8) / 8) * 8 - 8, "."), "latin1");
  const entry = Buffer.concat([u32(8 + payload.length), u16(0x0200), u16(0x0002), payload]);
  let table = entry;
  let declared = entry.length;
  let offset = image.length;
  let file = Buffer.concat([image, entry]);
  if (kind === "past_eof") offset = file.length + 0x1000;
  if (kind === "size_past") declared = entry.length + 0x2000;
  if (kind === "cut") file = file.subarray(0, image.length + 12);
  if (kind === "zero_size") declared = 0;
  if (kind === "misaligned") { file = Buffer.concat([image, Buffer.from([0, 0, 0]), entry]); offset = image.length + 3; }
  if (kind === "trailing") file = Buffer.concat([file, Buffer.from("OVERLAY-AFTER-THE-TABLE")]);
  if (kind === "short_entry") { table = Buffer.concat([u32(4), u16(0x0200), u16(0x0002), payload]); file = Buffer.concat([image, table]); declared = table.length; }
  if (kind === "empty_table") { table = Buffer.alloc(4); file = Buffer.concat([image, table]); declared = 4; }
  const out = Buffer.from(file);
  out.writeUInt32LE(offset, 0x80 + 4 + 20 + ddAt + 4 * 8);
  out.writeUInt32LE(declared, 0x80 + 4 + 20 + ddAt + 4 * 8 + 4);
  return out;
}

/** The stand-in `osslsigncode`: --version prints $VER; verify prints the captured output named by the SCENARIO marker in the file, with the trust files it was given echoed. */
async function fakeProgram(cwd: string, bin: string, ver = "2.5"): Promise<string> {
  const fix = join(cwd, "fixtures");
  await mkdir(fix, { recursive: true });
  for (const [name, cap] of Object.entries(CAP)) {
    await writeFile(join(fix, `${name}.out`), cap.out);
    await writeFile(join(fix, `${name}.exit`), String(cap.exit));
  }
  await stub(bin, "osslsigncode", `case "$1" in
--version) printf 'osslsigncode ${ver}, using:\\n\\tOpenSSL 3.0.7 1 Nov 2022 (Library: OpenSSL 3.0.22 25 Aug 2026)\\n'; exit 0;;
verify) shift
  ca=; tsa=; crl=; in=
  while [ $# -gt 0 ]; do case "$1" in -CAfile) ca="$2"; shift 2;; -TSA-CAfile) tsa="$2"; shift 2;; -CRLfile) crl="$2"; shift 2;; -time) shift 2;; -in) in="$2"; shift 2;; *) shift;; esac; done
  [ -n "$LOG" ] && printf 'verify CA=%s TSA=%s CRL=%s IN=%s\\n' "$ca" "$tsa" "$crl" "$in" >> "$LOG"
  name=$(grep -a -o 'SCENARIO:[a-z_]*' "$in" | head -1 | cut -d: -f2)
  case "$name" in
    hang) echo $$ > "$PIDS/prog.pid"; sleep 120; exit 0;;
    kid) ( while :; do echo late; sleep 0.05; done ) & echo $! > "$PIDS/kid.pid"; name=ok;;
    flood) echo $$ > "$PIDS/prog.pid"; yes 'Signature verification: ok' ; exit 0;;
    odd_exit) echo "something else"; exit 3;;
    spaces) { printf 'Signature Index: 1'; head -c 400000 /dev/zero | tr '\\0' ' '; printf 'x\n'; printf 'Message digest algorithm  : a'; head -c 400000 /dev/zero | tr '\\0' ' '; printf 'b\n'
              printf 'Calculated message digest : AB'; head -c 400000 /dev/zero | tr '\\0' ' '; printf '!\n'; printf 'Hash Algorithm: a'; head -c 400000 /dev/zero | tr '\\0' ' '; printf 'b\n'; echo Failed; }; exit 1;;
    manysigs) i=0; while [ $i -lt 20000 ]; do printf 'Signature Index: %s\nSignature verification: failed\n\n' $i; i=$((i+1)); done; echo "Number of verified signatures: 20000"; echo Failed; exit 1;;
    longname) { echo 'Signature Index: 0  (Primary Signature)'; printf 'Signer'"'"'s certificate:\n\tSigner #0:\n\t\tSubject: /CN='; head -c 3000000 /dev/zero | tr '\\0' 'a'; echo; echo 'Signature verification: failed'; echo 'Number of verified signatures: 1'; echo Failed; }; exit 1;;
  esac
  code=$(cat "${fix}/$name.exit")
  sed -e "s|^CAfile: .*|CAfile: $ca|" -e "s|^TSA's certificates file: .*|TSA's certificates file: $tsa|" -e "s|^CRLfile: .*|CRLfile: $crl|" "${fix}/$name.out" | case "$MUT" in
    extra) cat; echo "foo bar";;
    no_closing) grep -v '^Succeeded';;
    failed_word) sed 's/^Succeeded/Failed/';;
    no_digest) grep -v -E '^(Current|Calculated) message digest';;
    echo_off) sed 's|^CAfile: .*|CAfile: /elsewhere.pem|';;
    longline) cat; head -c 3000000 /dev/zero | tr '\0' 'a'; echo;;
    *) cat;;
  esac
  case "$MUT" in exit1) exit 1;; failed_word) exit 0;; esac
  exit $code;;
esac
exit 2`);
  return fix;
}

async function run(cwd: string, bin: string, scenario: string, args: Record<string, unknown> = {}, env: Record<string, string> = {}, table?: TableKind): Promise<Json> {
  await put(cwd, `work/${scenario}.exe`, pe({ scenario, table }));
  const out = await tool(AV, cwd, { path: `work/${scenario}.exe`, ...args }, env, bin);
  assert.doesNotMatch(out.stderr, /Traceback/);
  const answer = JSON.parse(out.stdout) as Json;
  assert.equal(out.code, ["complete", "partial"].includes(answer.status) ? 0 : 1, out.stdout);
  return answer;
}

const TRUST = { trust_ca: "work/ca.pem" };
async function trust(cwd: string): Promise<void> {
  await put(cwd, "work/ca.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
  await put(cwd, "work/tsa.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
  await put(cwd, "work/crl.pem", "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n");
}

test("a signature that the program verified against the supplied trust material is verified, and everything that was not supplied is not_checked", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    const a = await run(cwd, bin, "ok", TRUST);
    assert.equal(a.status, "complete", JSON.stringify(a));
    assert.equal(a.verification, "verified");
    assert.equal(a.signature_count, 1);
    const s = a.signatures[0];
    assert.equal(s.status, "verified");
    assert.equal(s.kind, "primary");
    assert.equal(s.digest_matches_file, true);
    assert.equal(s.signature_verification, "verified");
    assert.equal(s.revocation, "not_checked", "no revocation list was supplied");
    assert.equal(s.timestamp.status, "absent");
    assert.equal(s.digest_algorithm, "SHA256");
    assert.deepEqual(s.signer.not_before, { raw: "Jan  1 00:00:00 2026 GMT", utc: "2026-01-01T00:00:00Z" });
    assert.match(s.signer.subject, /Fixture Signer/);
    assert.equal(a.verifier.layout_checked_against, "2.5");
    assert.match(a.verifier.version_output, /^osslsigncode 2\.5/);
    assert.equal(a.trust.default_ca_store, "never read");
    assert.equal(a.certificate_table.present, true);
    assert.equal(a.certificate_table.entries[0].type_name, "PKCS_SIGNED_DATA");
    assert.equal(a.certificate_table.ends_at_end_of_file, true);
    assert.deepEqual(a.certificate_table.problems, []);
  });
});

test("without trust material no signature is verified: the digest is compared, the rest is not_checked, and the default CA store is never named to the program", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    const log = join(cwd, "argv.log");
    const a = await run(cwd, bin, "unusable", {}, { LOG: log });
    assert.equal(a.status, "complete", JSON.stringify(a));
    assert.equal(a.verification, "not_checked");
    assert.equal(a.signatures[0].status, "not_checked");
    assert.deepEqual(a.signatures[0].status_reasons, ["no_trust_material_supplied"]);
    assert.equal(a.signatures[0].digest_matches_file, true);
    assert.match(a.verification_basis, /no trust material was supplied/);
    assert.match(await readFile(log, "utf8"), /CA=\/dev\/null TSA=\/dev\/null CRL= IN=work\/unusable\.exe/);
    // a program that claims success with no trust material is not believed
    const b = await run(cwd, bin, "ok", {});
    assert.equal(b.verification, "not_checked");
    assert.equal(b.signatures[0].status, "not_checked");
    assert.equal(b.signatures[0].signature_verification, "not_checked");
  });
});

test("every argument the program is given comes from the call: both trust files are always named, a revocation list and a verification time only when supplied", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    const log = join(cwd, "argv.log");
    const a = await run(cwd, bin, "revoked", { ...TRUST, tsa_ca: "work/tsa.pem", crl: "work/crl.pem", verify_time: 1_700_000_000 }, { LOG: log });
    assert.equal(a.verifier.argv.join(" "), `${a.verifier.program} verify -CAfile work/ca.pem -TSA-CAfile work/tsa.pem -CRLfile work/crl.pem -time 1700000000 -in work/revoked.exe`);
    assert.match(await readFile(log, "utf8"), /CA=work\/ca\.pem TSA=work\/tsa\.pem CRL=work\/crl\.pem/);
    assert.equal(a.trust.verification_time, "2023-11-14T22:13:20Z");
  });
});

test("the failures the program reports are failed with a fixed reason: an untrusted chain, a changed file, a revoked certificate", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    const chain = await run(cwd, bin, "chain", TRUST);
    assert.equal(chain.status, "complete");
    assert.equal(chain.verification, "failed");
    assert.deepEqual(chain.signatures[0].status_reasons, ["chain_not_built_to_the_trust_material"]);
    assert.equal(chain.signatures[0].digest_matches_file, true);
    const digest = await run(cwd, bin, "digest", TRUST);
    assert.equal(digest.status, "complete", JSON.stringify(digest));
    assert.equal(digest.verification, "failed");
    assert.deepEqual(digest.signatures[0].status_reasons, ["digest_mismatch"]);
    assert.equal(digest.signatures[0].chain_trust, "not_evaluated_digest_mismatch", "the program does not evaluate the chain after a digest mismatch");
    assert.equal(digest.signatures[0].digest_matches_file, false);
    const revoked = await run(cwd, bin, "revoked", { ...TRUST, crl: "work/crl.pem" });
    assert.equal(revoked.verification, "failed");
    assert.equal(revoked.signatures[0].revocation, "revoked");
    assert.deepEqual(revoked.signatures[0].status_reasons, ["certificate_revoked"]);
    // the same output with no list supplied is not read as a revocation result
    const unlisted = await run(cwd, bin, "revoked", TRUST);
    assert.equal(unlisted.signatures[0].revocation, "not_checked");
  });
});

test("a timestamp counter-signature is read, and verified only against timestamp-authority material the call supplied", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    const ok = await run(cwd, bin, "ts_ok", { ...TRUST, tsa_ca: "work/tsa.pem" });
    assert.equal(ok.verification, "verified", JSON.stringify(ok));
    assert.equal(ok.signatures[0].timestamp.status, "verified");
    assert.equal(ok.signatures[0].timestamp.present, true);
    assert.equal(ok.signatures[0].timestamp.hash_algorithm, "sha256");
    assert.match(ok.signatures[0].timestamp.time.utc, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    assert.match(ok.signatures[0].timestamp.verified_by_issuer, /Fixture Root CA/);
    const none = await run(cwd, bin, "ts_none", TRUST);
    assert.equal(none.status, "complete", JSON.stringify(none));
    assert.equal(none.signatures[0].timestamp.status, "not_checked", "the program's failure to load a default store is not a failed timestamp");
    assert.equal(none.signatures[0].timestamp.present, true);
    const bad = await run(cwd, bin, "ts_bad", { ...TRUST, tsa_ca: "work/tsa.pem" });
    assert.equal(bad.signatures[0].timestamp.status, "failed");
    assert.equal(bad.signatures[0].signature_verification, "verified");
    assert.equal(bad.signatures[0].status, "failed", "the program's exit status is 0 here: a failed timestamp is not hidden by it");
    assert.equal(bad.verification, "failed");
    assert.deepEqual(bad.signatures[0].status_reasons, ["timestamp_not_verified_against_the_supplied_authority_material"]);
  });
});

test("a nested (second) signature is a record of its own", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    const a = await run(cwd, bin, "nested", TRUST);
    assert.equal(a.status, "complete", JSON.stringify(a));
    assert.equal(a.signature_count, 2);
    assert.deepEqual(a.signatures.map((s: Json) => [s.index, s.kind, s.status, s.digest_algorithm]), [[0, "primary", "verified", "SHA1"], [1, "nested", "verified", "SHA256"]]);
  });
});

test("an unsigned PE is unsigned; a PE32+ and a CLR header are named; a CLR strong-name signature is not Authenticode", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    await put(cwd, "work/plain.exe", pe({ table: "none", scenario: "unsigned" }));
    const a = body(await tool(AV, cwd, { path: "work/plain.exe", ...TRUST }, {}, bin));
    assert.equal(a.status, "complete", JSON.stringify(a));
    assert.equal(a.verification, "unsigned");
    assert.equal(a.signature_count, 0);
    assert.equal(a.certificate_table.present, false);
    await put(cwd, "work/clr.exe", pe({ table: "none", scenario: "unsigned", plus: true, clr: true }));
    const b = body(await tool(AV, cwd, { path: "work/clr.exe" }, {}, bin));
    assert.equal(b.pe.format, "PE32+");
    assert.equal(b.pe.clr_header_declared, true);
    assert.ok(b.notes.some((n: string) => /strong-name signature of a \.NET assembly is not an Authenticode signature/.test(n)));
  });
});

test("a certificate table that is cut, points past the end of the file, is misaligned, is not at the end or holds a short entry is said from the headers and from the program", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    const cases: [TableKind, RegExp][] = [
      ["past_eof", /past the end of the file/], ["size_past", /past the end of the file/], ["cut", /past the end of the file/],
      ["trailing", /not at the end of the file/], ["misaligned", /not a multiple of 8/], ["short_entry", /less than its 8-byte header/], ["zero_size", /size of 0/],
    ];
    for (const [kind, rx] of cases) {
      const a = await run(cwd, bin, "corrupt", TRUST, {}, kind).catch((e: Error) => { throw new Error(`${kind}: ${e.message.slice(0, 600)}`); });
      assert.equal(a.status, "complete", `${kind}: ${JSON.stringify(a)}`);
      assert.equal(a.verification, "failed", kind);
      assert.equal(a.signature_count, 0, kind);
      assert.ok(a.certificate_table.problems.some((p: string) => rx.test(p)), `${kind}: ${JSON.stringify(a.certificate_table.problems)}`);
      assert.deepEqual(a.problems, a.certificate_table.problems, kind);
    }
    // the program refuses a table the headers show nothing wrong with: the two disagree, so the answer is partial
    const odd = await run(cwd, bin, "corrupt", TRUST, {}, "ok");
    assert.equal(odd.status, "partial", JSON.stringify(odd));
    assert.match(odd.status_basis, /the two readings disagree/);
    assert.equal(odd.verification, "failed");
  });
});

test("a signature the file's own text imitates is not taken as verified: a description or URL attribute that carries the program's lines", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    const a = await run(cwd, bin, "inject", TRUST);
    assert.equal(a.status, "partial", JSON.stringify(a));
    assert.equal(a.verification, "not_checked");
    assert.match(a.status_basis, /ambiguous/);
    assert.deepEqual(a.signatures.map((s: Json) => [s.status, s.signature_verification, s.status_reasons]), [["not_checked", "not_checked", ["output_ambiguous", "output_not_read_whole"]]]);
    assert.ok(a.signatures[0].free_text_attributes_not_read >= 1);
    assert.doesNotMatch(JSON.stringify(a), /forged/i);
  });
});

test("a release other than the one the reading was checked against is not run; a program that answers nothing readable, or exits with another status, is failed", async () => {
  await withCwd(async (cwd, bin) => {
    const log = join(cwd, "argv.log");
    await fakeProgram(cwd, bin, "2.9");
    await trust(cwd);
    const a = await run(cwd, bin, "ok", TRUST, { LOG: log });
    assert.equal(a.status, "unsupported", JSON.stringify(a));
    assert.match(a.status_basis, /not the release this tool's reading/);
    assert.equal(a.verification, "not_checked");
    assert.equal(await readFile(log, "utf8").catch(() => ""), "", "verify was not started");
    await fakeProgram(cwd, bin, "2.5");
    const b = await run(cwd, bin, "odd_exit", TRUST);
    assert.equal(b.status, "failed");
    assert.match(b.status_basis, /exit status 3/);
    await stub(bin, "osslsigncode", "echo 'not a version'; exit 0");
    const c = refused(await tool(AV, cwd, { path: "work/ok.exe", ...TRUST }, {}, bin));
    assert.equal(c.status, "failed");
    assert.match(c.status_basis, /did not answer with a version/);
  });
});

test("the call's time limit ends the program and what it started, and says nothing was verified", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    await mkdir(join(cwd, "pids"), { recursive: true });
    const t0 = Date.now();
    const a = await run(cwd, bin, "hang", { ...TRUST, max_seconds: 5 }, { PIDS: join(cwd, "pids") });
    assert.equal(a.status, "partial", JSON.stringify(a));
    assert.deepEqual(a.limits_hit, ["time"]);
    assert.equal(a.verification, "not_checked");
    assert.equal(a.signature_count, null);
    assert.ok(Date.now() - t0 < 30_000);
    assert.ok(await gone(await pidFile(join(cwd, "pids", "prog.pid")), 10_000));
  });
});

test("a program that prints without end is ended at the output cap and the answer is partial", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    await mkdir(join(cwd, "pids"), { recursive: true });
    const a = await run(cwd, bin, "flood", TRUST, { PIDS: join(cwd, "pids") });
    assert.equal(a.status, "partial", JSON.stringify(a));
    assert.deepEqual(a.limits_hit, ["program_output_bytes"]);
    assert.equal(a.verification, "not_checked");
    assert.ok(await gone(await pidFile(join(cwd, "pids", "prog.pid")), 10_000));
  });
});

test("SIGTERM ends the program and answers with one document: failed, interrupted, exit 143", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    await mkdir(join(cwd, "pids"), { recursive: true });
    await put(cwd, "work/hang.exe", pe({ scenario: "hang" }));
    const r = startDetached(AV, cwd, { path: "work/hang.exe", ...TRUST }, { PIDS: join(cwd, "pids") }, bin);
    try {
      const pid = await pidFile(join(cwd, "pids", "prog.pid"));
      r.signal("SIGTERM");
      r.signal("SIGTERM");
      assert.equal(await r.closed, 143);
      const word = JSON.parse(r.stdout()) as Json;
      assert.equal(word.status, "failed");
      assert.equal(word.interrupted, true);
      assert.equal(word.stopped_by_signal, 15);
      assert.ok(await gone(pid, 10_000));
    } finally {
      try { r.signal("SIGKILL"); } catch { /* gone */ }
    }
  });
});

test("a link, a pipe, a directory, a missing file, a file that is not a PE, and a name with a line break are refused as JSON", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/real.exe", pe({ scenario: "ok" }));
    await symlink(join(cwd, "work/real.exe"), join(cwd, "work/link.exe"));
    assert.match(refused(await tool(AV, cwd, { path: "work/link.exe" }, {}, bin)).error, /symbolic link/);
    spawnSync("mkfifo", [join(cwd, "work/pipe.exe")]);
    const t0 = Date.now();
    assert.match(refused(await tool(AV, cwd, { path: "work/pipe.exe" }, {}, bin)).error, /named pipe/);
    assert.ok(Date.now() - t0 < 20_000);
    await mkdir(join(cwd, "work/d"), { recursive: true });
    assert.match(refused(await tool(AV, cwd, { path: "work/d" }, {}, bin)).error, /directory/);
    assert.match(refused(await tool(AV, cwd, { path: "work/none.exe" }, {}, bin)).error, /no such file/);
    await put(cwd, "work/text.txt", "just text\n");
    const t = refused(await tool(AV, cwd, { path: "work/text.txt" }, {}, bin));
    assert.equal(t.status, "unsupported");
    await put(cwd, "work/a\nb.exe", pe({ scenario: "ok" }));
    assert.match(refused(await tool(AV, cwd, { path: "work/a\nb.exe" }, {}, bin)).error, /line break/);
    assert.match(refused(await tool(AV, cwd, { path: "work/real.exe", trust_ca: "work/none.pem" }, {}, bin)).error, /trust_ca: no such file/);
    assert.match(refused(await tool(AV, cwd, { path: "work/real.exe", crl: "work/d" }, {}, bin)).error, /crl: not a regular file/);
  });
});

test("hostile parameters are refused as JSON, never a traceback", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    const cases: unknown[] = [null, [], "x", { path: 1 }, { path: "" }, { path: "a\u0000b" }, { path: "work/x", max_seconds: 0 }, { path: "work/x", max_seconds: 10 ** 9 }, { path: "work/x", max_seconds: true },
      { path: "work/x", max_seconds: 1.5 }, { path: "work/x", extra: 1 }, { path: "work/x", verify_time: -1 }, { path: "work/x", verify_time: 10 ** 12 }, { path: "work/x", verify_time: "1" },
      { path: "work/x", trust_ca: 5 }, { path: "work/x", tsa_ca: "" }, { path: "work/x", crl: "a\nb" }];
    for (const c of cases) refused(await tool(AV, cwd, c, {}, bin));
    let nest: unknown = [];
    for (let i = 0; i < 4000; i++) nest = [nest];
    const deep = await tool(AV, cwd, nest, {}, bin);
    assert.doesNotMatch(deep.stderr, /Traceback/);
    assert.notEqual(deep.code, 0);
    assert.doesNotThrow(() => JSON.parse(deep.stdout));
    const lone = await tool(AV, cwd, { path: "\ud800" }, {}, bin);
    assert.doesNotMatch(lone.stderr, /Traceback/);
    assert.doesNotThrow(() => JSON.parse(lone.stdout));
  });
});

test("hostile output from the program costs time in proportion to its size: long runs of spaces in the lines it is read by, 20,000 signatures, a name of 3 million characters", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    for (const scenario of ["spaces", "manysigs", "longname"]) {
      const t0 = Date.now();
      await put(cwd, `work/${scenario}.exe`, pe({ scenario }));
      const out = await tool(AV, cwd, { path: `work/${scenario}.exe`, ...TRUST }, {}, bin);
      assert.doesNotMatch(out.stderr, /Traceback/, scenario);
      const a = JSON.parse(out.stdout) as Json;
      assert.ok(Date.now() - t0 < 30_000, `${scenario}: ${Date.now() - t0} ms`);
      assert.notEqual(a.verification, "verified", scenario);
      if (scenario === "manysigs") {
        assert.equal(a.status, "partial", JSON.stringify(a).slice(0, 300));
        assert.equal(a.signatures.length, 64);
        assert.deepEqual(a.limits_hit, ["signatures", "output_not_read_whole"]);
      }
      if (scenario === "longname") assert.match(JSON.stringify(a), /a name of 3\d{6} characters/);
    }
  });
});

const have = (name: string): boolean => spawnSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8" }).status === 0;

test("without osslsigncode the tool says so, as JSON", { skip: have("osslsigncode") ? "osslsigncode is installed on this machine" : false }, async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "work/x.exe", pe({ scenario: "ok" }));
    assert.match(refused(await tool(AV, cwd, { path: "work/x.exe" }, {}, bin)).error, /osslsigncode is not installed/);
  });
});

test("names out of a certificate are withheld by shape: canaries of every shape in the subject, the issuer and the timestamp issuer never reach the answer", async () => {
  await withCwd(async (cwd, bin) => {
    const fix = await fakeProgram(cwd, bin);
    await trust(cwd);
    let planted = 0;
    let leaked = 0;
    const misses: string[] = [];
    for (let seed = 1; seed <= 12; seed++) {
      const rnd = prng(seed);
      for (const [shape, make] of Object.entries(SHAPES)) {
        const c = make(120, rnd);
        if (!c) continue;
        const text = (await readFile(join(fix, "ts_ok.out"), "utf8"))
          .replaceAll("/CN=Fixture Signer/O=Fixture Org", `/CN=${c.plant}/O=Org ${c.plant}`)
          .replaceAll("/CN=Fixture Root CA/O=Fixture Org", `/CN=${c.plant}/O=Issuer ${c.plant}`);
        await writeFile(join(fix, "canary.out"), text);
        await writeFile(join(fix, "canary.exit"), "0");
        planted++;
        await put(cwd, "work/canary.exe", pe({ scenario: "canary" }));
        const out = await tool(AV, cwd, { path: "work/canary.exe", ...TRUST, tsa_ca: "work/tsa.pem" }, {}, bin);
        const hay = Buffer.from(out.stdout + out.stderr, "latin1");
        const found = needles(c).filter((n) => hay.includes(n.bytes));
        if (found.length) { leaked++; misses.push(`${shape}#${seed}`); }
      }
    }
    assert.ok(planted >= 100, `${planted} canaries planted`);
    assert.equal(leaked, 0, `canaries that reached the answer: ${misses.join(", ")}`);
    void forms;
  });
});

// ---- the real program --------------------------------------------------------------------------------------------------------------

const real = have("osslsigncode") && have("openssl");
// The image carries Debian 12's osslsigncode 2.5, the release whose words the tool was checked against; any other release is `unsupported`.
const OSSL_RELEASE = real ? /^osslsigncode (\d+\.\d+)/.exec(spawnSync("osslsigncode", ["--version"], { encoding: "utf8" }).stdout ?? "")?.[1] ?? "unknown" : "";
const SKIP = !real ? "osslsigncode and openssl are not both installed on this machine"
  : OSSL_RELEASE !== "2.5" ? `osslsigncode here is ${OSSL_RELEASE}, not 2.5: the case below holds that it is unsupported` : false;

function sh(cwd: string, cmd: string): string {
  const r = spawnSync("sh", ["-c", cmd], { cwd, encoding: "utf8" });
  assert.equal(r.status, 0, `${cmd}\n${r.stdout}${r.stderr}`);
  return r.stdout;
}

/** Throwaway certificates: a root, a code-signing leaf, a time-stamping leaf, and an unrelated root. */
async function authority(cwd: string): Promise<void> {
  await writeFile(join(cwd, "code.ext"), "basicConstraints=CA:FALSE\nextendedKeyUsage=codeSigning\n");
  await writeFile(join(cwd, "tsa.ext"), "basicConstraints=CA:FALSE\nextendedKeyUsage=critical,timeStamping\n");
  sh(cwd, `openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=Fixture Root CA/O=Fixture Org" -days 3650 -addext basicConstraints=critical,CA:TRUE 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.pem -subj "/CN=Unrelated CA/O=Other Org" -days 3650 -addext basicConstraints=critical,CA:TRUE 2>/dev/null
for n in leaf tsa; do
  ext=code.ext; [ $n = tsa ] && ext=tsa.ext
  openssl req -newkey rsa:2048 -nodes -keyout $n.key -out $n.csr -subj "/CN=Fixture $n/O=Fixture Org" 2>/dev/null
  openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out $n.pem -days 3650 -extfile $ext 2>/dev/null
done`);
}

test("with the real osslsigncode: a PE signed here verifies against its root only, a changed byte fails, an unsigned file is unsigned, and the program's version is recorded", { skip: SKIP }, async () => {
  await withCwd(async (cwd) => {
    await authority(cwd);
    await writeFile(join(cwd, "plain.exe"), pe({ table: "none" }));
    sh(cwd, "osslsigncode sign -certs leaf.pem -key leaf.key -h sha256 -in plain.exe -out signed.exe >/dev/null");
    const ok = body(await tool(AV, cwd, { path: "signed.exe", trust_ca: "ca.pem" }));
    assert.equal(ok.status, "complete", JSON.stringify(ok));
    assert.equal(ok.verification, "verified");
    assert.match(ok.verifier.version_output, /^osslsigncode 2\.5/, "the layout checks in this file are for 2.5; another release is `unsupported`");
    assert.equal(ok.signatures[0].signature_verification, "verified");
    assert.match(ok.signatures[0].signer.subject, /Fixture leaf/);
    const other = body(await tool(AV, cwd, { path: "signed.exe", trust_ca: "other.pem" }));
    assert.equal(other.verification, "failed");
    assert.deepEqual(other.signatures[0].status_reasons, ["chain_not_built_to_the_trust_material"]);
    const none = body(await tool(AV, cwd, { path: "signed.exe" }));
    assert.equal(none.verification, "not_checked");
    assert.equal(none.signatures[0].digest_matches_file, true);
    const changed = Buffer.from(await readFile(join(cwd, "signed.exe")));
    changed[0x300] ^= 1;
    await writeFile(join(cwd, "changed.exe"), changed);
    const bad = body(await tool(AV, cwd, { path: "changed.exe", trust_ca: "ca.pem" }));
    assert.equal(bad.verification, "failed");
    assert.deepEqual(bad.signatures[0].status_reasons, ["digest_mismatch"]);
    const un = body(await tool(AV, cwd, { path: "plain.exe" }));
    assert.equal(un.verification, "unsigned");
    const cut = (await readFile(join(cwd, "signed.exe"))).subarray(0, -300);
    await writeFile(join(cwd, "cut.exe"), cut);
    const c = body(await tool(AV, cwd, { path: "cut.exe", trust_ca: "ca.pem" }));
    assert.equal(c.verification, "failed");
    assert.ok(c.certificate_table.problems.length > 0);
    sh(cwd, "osslsigncode sign -certs leaf.pem -key leaf.key -h sha1 -in plain.exe -out s1.exe >/dev/null; osslsigncode sign -nest -certs leaf.pem -key leaf.key -h sha256 -in s1.exe -out nested.exe >/dev/null");
    const nested = body(await tool(AV, cwd, { path: "nested.exe", trust_ca: "ca.pem" }));
    assert.equal(nested.signature_count, 2, JSON.stringify(nested));
    assert.equal(nested.verification, "verified");
    await writeFile(join(cwd, "plain64.exe"), pe({ table: "none", plus: true }));
    sh(cwd, "osslsigncode sign -certs leaf.pem -key leaf.key -h sha256 -in plain64.exe -out signed64.exe >/dev/null");
    assert.equal(body(await tool(AV, cwd, { path: "signed64.exe", trust_ca: "ca.pem" })).verification, "verified");
  });
});

const TSA_SERVER = `import http.server, subprocess, sys
D = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        q = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        open(D + "/q.tsq", "wb").write(q)
        r = subprocess.run(["openssl", "ts", "-reply", "-queryfile", D + "/q.tsq", "-config", D + "/tsa.cnf", "-out", D + "/r.tsr"], capture_output=True)
        if r.returncode != 0:
            self.send_response(500); self.end_headers(); return
        data = open(D + "/r.tsr", "rb").read()
        self.send_response(200); self.send_header("Content-Type", "application/timestamp-reply"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
open(D + "/port", "w").write(str(srv.server_address[1]))
srv.serve_forever()
`;

test("with the real osslsigncode and a local time-stamp authority: the counter-signature is read, verified against the authority's root, and failed against an unrelated one", { skip: SKIP }, async () => {
  await withCwd(async (cwd) => {
    await authority(cwd);
    await writeFile(join(cwd, "tsa.cnf"), `[tsa]\ndefault_tsa = t\n[t]\ndir = ${cwd}\nserial = ${cwd}/tsaserial\ncrypto_device = builtin\nsigner_cert = ${cwd}/tsa.pem\nsigner_key = ${cwd}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\nother_policies = 1.2.3.4.5\ndigests = sha1, sha256\naccuracy = secs:1\nordering = yes\ntsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n`);
    await writeFile(join(cwd, "tsaserial"), "01\n");
    await writeFile(join(cwd, "tsa_server.py"), TSA_SERVER);
    await writeFile(join(cwd, "plain.exe"), pe({ table: "none" }));
    const server = startDetached(join(cwd, "tsa_server.py"), cwd, {}, {}, undefined, [cwd]);
    try {
      const port = Number((await (async () => { for (let i = 0; i < 100; i++) { const t = await readFile(join(cwd, "port"), "utf8").catch(() => ""); if (t) return t; await new Promise((r) => setTimeout(r, 50)); } throw new Error("no port"); })()));
      sh(cwd, `osslsigncode sign -certs leaf.pem -key leaf.key -h sha256 -ts http://127.0.0.1:${port} -in plain.exe -out stamped.exe >/dev/null`);
    } finally {
      try { server.signal("SIGKILL"); } catch { /* gone */ }
    }
    const ok = body(await tool(AV, cwd, { path: "stamped.exe", trust_ca: "ca.pem", tsa_ca: "ca.pem" }));
    assert.equal(ok.verification, "verified", JSON.stringify(ok));
    assert.equal(ok.signatures[0].timestamp.status, "verified");
    assert.equal(ok.signatures[0].timestamp.present, true);
    assert.match(ok.signatures[0].timestamp.time.utc, /^\d{4}-/);
    const unchecked = body(await tool(AV, cwd, { path: "stamped.exe", trust_ca: "ca.pem" }));
    assert.equal(unchecked.signatures[0].timestamp.status, "not_checked");
    const bad = body(await tool(AV, cwd, { path: "stamped.exe", trust_ca: "ca.pem", tsa_ca: "other.pem" }));
    assert.equal(bad.signatures[0].timestamp.status, "failed");
    assert.equal(bad.verification, "failed");
  });
});

test("with a real osslsigncode of another release than 2.5: nothing is verified, and the answer is unsupported and names the release", { skip: !real ? "osslsigncode and openssl are not both installed on this machine" : OSSL_RELEASE === "2.5" ? "osslsigncode here is 2.5: the cases above read it" : false }, async () => {
  await withCwd(async (cwd) => {
    await authority(cwd);
    await writeFile(join(cwd, "plain.exe"), pe({ table: "none" }));
    sh(cwd, "osslsigncode sign -certs leaf.pem -key leaf.key -h sha256 -in plain.exe -out signed.exe >/dev/null");
    const a = refused(await tool(AV, cwd, { path: "signed.exe", trust_ca: "ca.pem" }));          // an answer that is not complete or partial exits 1
    assert.equal(a.status, "unsupported", JSON.stringify(a));
    assert.ok(a.status_basis.startsWith(`osslsigncode ${OSSL_RELEASE} is not the release this tool's reading of the program's words was checked against (2.5): nothing was verified`), a.status_basis);
    assert.equal(a.verification, "not_checked");
  });
});

test("output that was not read whole and clean is never a verification: a line no rule knows, a missing or disagreeing closing word, an exit status that disagrees, a trust file not echoed, a missing digest line, a 3 MB line", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    const both = { trust_ca: "work/ca.pem", tsa_ca: "work/tsa.pem" };
    const clean = await run(cwd, bin, "ok", both);
    assert.equal(clean.verification, "verified", "the unmutated output is a verification");
    for (const mut of ["extra", "no_closing", "failed_word", "exit1", "no_digest", "echo_off", "longline"]) {
      const a = await run(cwd, bin, "ok", both, { MUT: mut });
      const why = `${mut}: ${JSON.stringify(a).slice(0, 700)}`;
      assert.equal(a.status, "partial", why);
      assert.notEqual(a.verification, "verified", why);
      assert.equal(a.signatures[0].status, "not_checked", why);
      assert.equal(a.signatures[0].signature_verification, "not_checked", why);
      assert.equal(a.signatures[0].revocation, "not_checked", why);
      assert.ok(a.limits_hit.includes("output_not_read_whole"), why);
      assert.doesNotMatch(a.status_basis, /every signature verified/, why);
    }
  });
});

test("a process the program leaves behind holding its output pipe is ended with the tool's answer: nothing is left running, and a late line is not taken as the program's report", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await trust(cwd);
    await mkdir(join(cwd, "pids"), { recursive: true });
    let kid = 0;
    try {
      const t0 = Date.now();
      const a = await run(cwd, bin, "kid", TRUST, { PIDS: join(cwd, "pids") });
      kid = await pidFile(join(cwd, "pids", "kid.pid"), 3_000).catch(() => 0);
      assert.ok(kid, "the program recorded its child's pid");
      assert.ok(Date.now() - t0 < 30_000);
      assert.ok(await gone(kid, 5_000), "the child that held the pipe is ended by the tool");
      assert.ok(a.status === "complete" ? a.verification === "verified" : true, "a complete answer is the program's own report: " + JSON.stringify(a).slice(0, 300));
    } finally {
      if (kid) { try { process.kill(kid, "SIGKILL"); } catch { /* gone */ } }
    }
  });
});

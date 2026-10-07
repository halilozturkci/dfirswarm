/**
 * Credential formats for the cloud pack's withholding tests. Every value is built here from a published prefix and a
 * deterministic pseudo-random body, never written out whole: a literal that looks like a live token is refused by the host's
 * push protection, and a test must not depend on a secret that exists. The bodies are random-looking on purpose (mixed case and
 * digits in the proportions real keys have); the lengths and alphabets are the formats' own.
 */
import { createHash } from "node:crypto";

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = LOWER.toUpperCase();
const DIGITS = "0123456789";
export const ALNUM = UPPER + LOWER + DIGITS;
const URLSAFE = ALNUM + "_-";
const B64 = ALNUM + "+/";

/** A deterministic byte stream: sha256 of (seed, counter). */
function bytes(seed: number, n: number): Buffer {
  const out: Buffer[] = [];
  for (let i = 0; out.reduce((a, b) => a + b.length, 0) < n; i++) out.push(createHash("sha256").update(`cloud-pack-secrets:${seed}:${i}`).digest());
  return Buffer.concat(out).subarray(0, n);
}

/** `n` characters of `alphabet`, mixed so that upper case, lower case and digits are all present when the alphabet has them. */
export function rnd(n: number, seed: number, alphabet = ALNUM): string {
  const b = bytes(seed, n);
  let text = "";
  for (let i = 0; i < n; i++) text += alphabet[b[i] % alphabet.length];
  return text;
}

const b64 = (b: Buffer): string => b.toString("base64");
const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");
const hex = (s: string, algo: string): string => createHash(algo).update(s).digest("hex");

export const AKID = "AKIA" + "IOSFODNN7EXAMPLE"; // the documented example key id: an identifier, which must stay
export const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"; // the documented example secret: 40 characters with slashes
export const AWS_SECRET2 = rnd(18, 1) + "/" + rnd(10, 2) + "+" + rnd(10, 3);
const AZ_NEW = rnd(3, 4) + "8Q~" + rnd(34, 5, URLSAFE + ".~");
const AZ_NEW_DOT = "." + rnd(2, 6) + "8Q~" + rnd(34, 7, URLSAFE + ".~");
const AZ_NEW_TILDE = rnd(1, 8) + "~" + rnd(1, 9) + "8Q~" + rnd(34, 10, URLSAFE);
const AZ_OLD32 = b64(bytes(11, 24));
const AZ_OLD44 = b64(bytes(12, 32));
const YA29 = "ya29." + rnd(150, 13, URLSAFE);
const G_REFRESH = "1//0" + rnd(100, 14, URLSAFE);
const GHP = "gh" + "p_" + rnd(36, 15);
const GHO = "gh" + "o_" + rnd(36, 16);
const GHS = "gh" + "s_" + rnd(36, 17);
const GHPAT = "github" + "_pat_11" + rnd(20, 18, UPPER + DIGITS) + "_" + rnd(59, 19);
export const JWT = b64u('{"alg":"RS256","typ":"JWT"}') + "." + b64u(`{"sub":"${rnd(20, 20)}","aud":"api"}`) + "." + rnd(86, 21, URLSAFE);
const JWT_SHORT = b64u('{"alg":"HS256"}') + "." + b64u("{}") + "." + rnd(43, 22, URLSAFE);
const JWT_NONE = b64u('{"alg":"none"}') + "." + b64u(`{"sub":"${rnd(12, 23)}"}`) + ".";
const OPAQUE32 = rnd(32, 24);
const OPAQUE12 = rnd(12, 25);
const enc = (s: string): string => s.replaceAll("+", "%2B").replaceAll("/", "%2F").replaceAll("=", "%3D");
const SAS_SIG = enc(b64(bytes(26, 32)));
const S3_SIG = hex("x", "sha256");
const S3_TOKEN = "IQoJb3JpZ2lu" + rnd(300, 27, B64);
const ESTS = "0.A" + rnd(400, 28, URLSAFE);
const SESSION_COOKIE = "s%3A" + rnd(24, 29) + "." + rnd(43, 30, URLSAFE);
const SESSIONID = hex("y", "md5");
const BASIC_LONG = b64(Buffer.from("user:Passw0rd!"));
const BASIC_SHORT = b64(Buffer.from("user:pass"));
const BASIC_ROOT = b64(Buffer.from("root:toor"));
const PW = "Summer2024!";
const PW_SPACE = "Correct Horse Battery Staple";
const PW_SEMI = "Summer;2024x";
const PW_SHORT = "a9!";
const ACCOUNT_KEY = b64(bytes(31, 64));
const SB_KEY = b64(bytes(32, 32));
const SLACK = "xo" + "xb-" + "1234567890-0987654321-" + rnd(24, 33);
const STRIPE = "sk" + "_live_" + rnd(24, 34);
const PEM_BODY = Array.from({ length: 6 }, (_, i) => b64(bytes(35 + i, 48))).join("\n");
const PEM = "-----BEGIN RSA PRIVATE KEY-----\n" + PEM_BODY + "\n-----END RSA PRIVATE KEY-----";
const NTLM = hex("z", "md5");
const URL_PASSWORD = "Pg" + rnd(10, 40) + "!x9";
const GOOGLE_CLIENT_SECRET = "GOC" + "SPX" + "-" + rnd(28, 41, URLSAFE);
const FUNCTION_KEY = rnd(54, 42, URLSAFE) + "==";
const JWE = [b64u('{"alg":"RSA-OAEP","enc":"A256GCM"}'), rnd(120, 43, URLSAFE), rnd(16, 44, URLSAFE), rnd(60, 45, URLSAFE), rnd(22, 46, URLSAFE)].join(".");

/** [label, the secret itself, the text it sits in]. */
export const TEXT_CASES: Array<[string, string, string]> = [
  ["aws key id and secret, assigned", AWS_SECRET, `aws_access_key_id=${AKID} aws_secret_access_key=${AWS_SECRET}`],
  ["aws secret in JSON text", AWS_SECRET2, `{"AccessKeyId": "${AKID}", "SecretAccessKey": "${AWS_SECRET2}"}`],
  ["aws secret bare after its id", AWS_SECRET2, `keys ${AKID} ${AWS_SECRET2}`],
  ["aws secret JSON-escaped", AWS_SECRET, `{\\"SecretAccessKey\\":\\"${AWS_SECRET.replaceAll("/", "\\/")}\\"}`],
  ["azure client secret", AZ_NEW, `client secret ${AZ_NEW} set`],
  ["azure client secret starting with a dot", AZ_NEW_DOT, `client secret ${AZ_NEW_DOT} set`],
  ["azure client secret with a tilde early", AZ_NEW_TILDE, `client secret ${AZ_NEW_TILDE} set`],
  ["azure old 32-character key", AZ_OLD32, `New-AzureADApplicationPasswordCredential -Value ${AZ_OLD32}`],
  ["azure old 44-character key", AZ_OLD44, `key ${AZ_OLD44}`],
  ["google access token in a header", YA29, `Authorization: Bearer ${YA29}`],
  ["google access token bare", YA29, `token ${YA29}`],
  ["google refresh token", G_REFRESH, `refresh with ${G_REFRESH}`],
  ["github ghp token in a URL", GHP, `git clone https://${GHP}@github.com/o/r`],
  ["github gho token", GHO, `oauth ${GHO}`],
  ["github ghs token", GHS, `app ${GHS}`],
  ["github fine-grained token", GHPAT, `pat ${GHPAT}`],
  ["jwt", JWT, `id ${JWT}`],
  ["jwt with a short payload", JWT_SHORT, `id ${JWT_SHORT}`],
  ["jwt with alg none", JWT_NONE, `id ${JWT_NONE}`],
  ["jwt in a URL fragment", JWT, `https://app.example.com/cb#id_token=${JWT}&state=x`],
  ["opaque access_token in a query", OPAQUE32, `https://app.example.com/cb?access_token=${OPAQUE32}&expires_in=3599`],
  ["SAS signature", SAS_SIG, `https://acct.blob.core.windows.net/c/b.zip?sv=2021-08-06&ss=b&srt=sco&sp=rl&se=2026-03-01T00:00:00Z&spr=https&sig=${SAS_SIG}`],
  ["S3 presigned signature", S3_SIG, `https://b.s3.amazonaws.com/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${AKID}%2F20260214%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260214T090000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=${S3_SIG}`],
  ["S3 presigned security token", S3_TOKEN, `https://b.s3.amazonaws.com/k?X-Amz-Security-Token=${enc(S3_TOKEN)}&X-Amz-Signature=${S3_SIG}`],
  ["ESTSAUTH cookie", ESTS, `Cookie: ESTSAUTH=${ESTS}; ESTSAUTHPERSISTENT=${ESTS}`],
  ["session cookie", SESSION_COOKIE, `Cookie: session=${SESSION_COOKIE}; theme=dark`],
  ["sessionid cookie", SESSIONID, `Cookie: a=b; sessionid=${SESSIONID}`],
  ["basic authorization, long", BASIC_LONG, `Authorization: Basic ${BASIC_LONG}`],
  ["basic authorization, user:pass", BASIC_SHORT, `Authorization: Basic ${BASIC_SHORT}`],
  ["basic authorization, root:toor", BASIC_ROOT, `Authorization: Basic ${BASIC_ROOT}`],
  ["bearer, 32 opaque characters", OPAQUE32, `Authorization: Bearer ${OPAQUE32}`],
  ["bearer, 12 opaque characters", OPAQUE12, `Authorization: Bearer ${OPAQUE12}`],
  ["password: in prose", PW, `login failed, password: ${PW}`],
  ["-Password switch", PW, `New-LocalUser -Name x -Password '${PW}'`],
  ["ConvertTo-SecureString", PW, `$p = ConvertTo-SecureString '${PW}' -AsPlainText -Force`],
  ["Pwd= in a connection string", PW, `Server=db;Uid=sa;Pwd=${PW};`],
  ["quoted password with spaces", PW_SPACE, `password="${PW_SPACE}"`],
  ["password with a semicolon", PW_SEMI, `password=${PW_SEMI} end`],
  ["password of three characters", PW_SHORT, `pwd=${PW_SHORT}`],
  ["dbPassword=", PW, `dbPassword=${PW}`],
  ["adminpassword:", PW, `adminpassword: ${PW}`],
  ["URL-encoded password", PW, `q=user%3Dbob%26password%3D${PW.replace("!", "%21")}`],
  ["JSON-escaped password", PW, `{\\"password\\":\\"${PW}\\"}`],
  ["storage connection string", ACCOUNT_KEY, `DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=${ACCOUNT_KEY};EndpointSuffix=core.windows.net`],
  ["service bus connection string", SB_KEY, `Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=${SB_KEY}`],
  ["slack bot token", SLACK, `notify ${SLACK}`],
  ["stripe live key", STRIPE, `charge with ${STRIPE}`],
  ["private key block", PEM_BODY.split("\n")[2], PEM],
  ["key block without its header line", PEM_BODY.split("\n")[2], PEM_BODY + "\n-----END RSA PRIVATE KEY-----"],
  ["ntlm hash pair", NTLM, `aad3b435b51404eeaad3b435b51404ee:${NTLM}`],
  ["a password in a connection URL", URL_PASSWORD, `DATABASE_URL=postgres://app:${URL_PASSWORD}@db.internal:5432/app`],
  ["a password in an amqps URL", URL_PASSWORD, `amqps://guest:${URL_PASSWORD}@rabbit.example.com`],
  ["a Google OAuth client secret", GOOGLE_CLIENT_SECRET, `client_id=123-abc.apps.googleusercontent.com secret ${GOOGLE_CLIENT_SECRET}`],
  ["an Azure Functions key in the query", FUNCTION_KEY, `https://func.azurewebsites.net/api/run?code=${FUNCTION_KEY}&name=a`],
  ["an Azure Functions key in the header", FUNCTION_KEY, `x-functions-key: ${FUNCTION_KEY}`],
  ["a JWE with five parts", JWE.split(".")[3], `token ${JWE}`],
];

/** [field name, its value]: a credential under a name that says so, with no shape to give it away. */
export const NAMED_CASES: Array<[string, string | number]> = [
  ["aws_secret_access_key", AWS_SECRET2], ["AWSSecretKey", AWS_SECRET2], ["SecretAccessKey", AWS_SECRET2],
  ["secretText", AZ_OLD44], ["keyValue", AZ_OLD44], ["AccountKey", ACCOUNT_KEY], ["primaryKey", ACCOUNT_KEY],
  ["tokenCode", "482913"], ["mfaCode", "482913"], ["pin", 1234], ["passwordHash", NTLM], ["ntHash", NTLM],
  ["x-api-key", OPAQUE32], ["Ocp-Apim-Subscription-Key", SESSIONID], ["plaintext", PW], ["userPassword", PW],
  ["Password", PW], ["db_pass", PW], ["pass", PW], ["cookie", "ESTSAUTH=" + ESTS], ["Cookie", "a=b"],
  ["privateKey", PEM], ["authorization", "Basic " + BASIC_SHORT], ["sessionToken", S3_TOKEN],
];

/** Identifiers that look a little like secrets and are not: they must stay in the answer, because they are evidence. */
export const CONTROLS: Array<[string, string]> = [
  ["a documented access key id", AKID],
  ["a Secrets Manager ARN", "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-AbCdEf"],
  ["a KMS key ARN", "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"],
  ["a GUID", "11111111-2222-3333-4444-555555555555"],
  ["a SHA-256 in hex", hex("a", "sha256")],
  ["a SHA-1 in hex", hex("a", "sha1")],
  ["a CloudFormation client request token", "Console-CreateStack-7f2d"],
  ["a role session name", "arn:aws:sts::111122223333:assumed-role/Admin/alice-session-20260214"],
  ["a pagination token in a query", "nextToken=AbCdEf123456"],
  ["prose that uses the word pass", "pass: 3 attempts remain"],
  ["a URL with a port and no user", "https://example.com:8443/path"],
];

/** The windows of a secret an output must not contain: every 8 characters, or the whole value when it is shorter. */
export function windows(secret: string, size = 8): string[] {
  if (secret.length <= size) return [secret];
  const out: string[] = [];
  for (let i = 0; i + size <= secret.length; i++) out.push(secret.slice(i, i + size));
  return out;
}

/** The first window of `secret` found in `haystack`, or undefined. */
export function leaked(secret: string, haystack: string): string | undefined {
  return windows(secret).find((w) => haystack.includes(w));
}

/**
 * Random, realistic secret canaries for the triage-collection suites, as Python source the tests exec next to the tools: one
 * generator per shape of the vendors' public formats (a prefix and a random body, base64 of random bytes, a connection string
 * with a random password, ...), never one hand-built string per shape. Each generator takes a seeded `random.Random` and
 * returns (text, cores): `text` is what is planted, `cores` are the random parts whose 12-character windows must not come back
 * in any output.
 *
 * LISTED are the shapes the withholding names; UNLISTED are the families and encodings it must also catch since the reviewers
 * measured them printed whole (GitLab, Stripe, Google, npm, SendGrid, ya29, DigitalOcean and Twilio keys, AWS-secret-shaped and
 * base64 keys with a slash, case-folded and full-width prefixes, NUL, zero-width and UTF-16 splits); RESIDUAL are the shapes no
 * rule here claims (a plain password alone in a name, text that only reads like a word): a test asserts they ARE printed, so
 * the sentence in the manifest, the changelog and the skills ("withholding is by shape") stays true.
 */
export const CANARY_PY = String.raw`
import base64, random, string

A62 = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
B64 = A62 + "+/"
B64U = A62 + "-_"
UP36 = string.ascii_uppercase + string.digits
LOW36 = string.ascii_lowercase + string.digits


def rs(r, alpha, n):
    return "".join(r.choice(alpha) for _ in range(n))


def b64_of(r, nbytes, slash=True, plus=False):
    while True:
        s = base64.b64encode(bytes(r.randrange(256) for _ in range(nbytes))).decode()
        if (slash and "/" not in s) or (plus and "+" not in s):
            continue
        return s


SHAPES = {}      # name -> (generator, usable as one file name)


def shape(name, safe=True, group="listed"):
    def wrap(fn):
        SHAPES[name] = (fn, safe, group)
        return fn
    return wrap


@shape("ghp")
def _(r):
    s = rs(r, A62, 36); return "ghp_" + s, [s]
@shape("gho")
def _(r):
    s = rs(r, A62, 36); return "gho_" + s, [s]
@shape("github_pat")
def _(r):
    a, b = rs(r, A62, 22), rs(r, A62, 59); return "github_pat_%s_%s" % (a, b), [a, b]
@shape("akia")
def _(r):
    s = rs(r, UP36, 16); return "AKIA" + s, [s]
@shape("asia")
def _(r):
    s = rs(r, UP36, 16); return "ASIA" + s, [s]
@shape("xoxb")
def _(r):
    a, b, c = rs(r, string.digits, 11), rs(r, string.digits, 12), rs(r, A62, 24); return "xoxb-%s-%s-%s" % (a, b, c), [a, b, c]
@shape("sk_openai")
def _(r):
    s = rs(r, A62, 48); return "sk-" + s, [s]
@shape("sk_proj")
def _(r):
    s = rs(r, B64U, 60); return "sk-proj-" + s, [s]
@shape("jwt")
def _(r):
    h = "eyJ" + rs(r, B64U, 33); p = "eyJ" + rs(r, B64U, 60); s = rs(r, B64U, 43)
    return "%s.%s.%s" % (h, p, s), [p, s]
@shape("pem_one_line", safe=False)
def _(r):
    body = rs(r, B64, 64); return "-----BEGIN RSA PRIVATE KEY----- %s -----END RSA PRIVATE KEY-----" % body, [body]
@shape("pem_multi", safe=False)
def _(r):
    lines = [rs(r, B64, 64) for _ in range(5)]
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----" % "\n".join(lines), lines
@shape("pem_no_end", safe=False)
def _(r):
    lines = [rs(r, B64, 64) for _ in range(3)]
    return "-----BEGIN PRIVATE KEY-----\n%s" % "\n".join(lines), lines
@shape("conn_postgres", safe=False)
def _(r):
    p = rs(r, A62, 14); return "postgres://%s:%s@db%d.example.test:5432/app" % (rs(r, LOW36, 6), p, r.randrange(99)), [p]
@shape("conn_mongo", safe=False)
def _(r):
    p = rs(r, A62, 16); return "mongodb+srv://%s:%s@cluster%d.example.test/db" % (rs(r, LOW36, 6), p, r.randrange(99)), [p]
@shape("conn_redis", safe=False)
def _(r):
    p = rs(r, A62, 20); return "redis://:%s@cache.example.test:6379/0" % p, [p]
@shape("conn_mssql", safe=False)
def _(r):
    p = rs(r, A62 + "!#$%^*", 14); return "Server=tcp:db.example.test,1433;Database=app;User Id=sa;Password=%s;Encrypt=True;" % p, [p]
@shape("conn_pwd_semicolon", safe=False)
def _(r):
    p = rs(r, A62, 12); return "Data Source=srv;Initial Catalog=x;pwd=%s;" % p, [p]
@shape("userinfo_at_in_password", safe=False)
def _(r):
    p = rs(r, A62, 6) + "@" + rs(r, A62, 10); return "ftp://svc%d:%s@10.%d.%d.%d/drop" % (r.randrange(99), p, r.randrange(256), r.randrange(256), r.randrange(256)), [p]
@shape("userinfo_slash_in_password", safe=False)
def _(r):
    p = rs(r, A62, 6) + "/" + rs(r, A62, 10); return "https://adm:%s@files%d.example.test/x" % (p, r.randrange(99)), [p]
@shape("userinfo_hash_or_question", safe=False)
def _(r):
    p = rs(r, A62, 6) + r.choice("#?") + rs(r, A62, 10); return "https://adm:%s@files.example.test/x" % p, [p]
@shape("userinfo_plain", safe=False)
def _(r):
    p = rs(r, A62, 14); return "https://bob:%s@git.example.test/repo.git" % p, [p]
@shape("userinfo_bare")
def _(r):
    p = rs(r, A62, 12); return "bob:%s@git%d.example.test" % (p, r.randrange(9)), [p]
@shape("userinfo_percent_encoded_at", safe=False)
def _(r):
    p = rs(r, A62, 8) + "%40" + rs(r, A62, 8); return "https://bob:%s@git.example.test/x" % p, [p]
@shape("aws_secret_kv", safe=False)
def _(r):
    s = rs(r, A62 + "/+", 40); return "aws_secret_access_key = " + s, [s]
@shape("password_kv")
def _(r):
    p = rs(r, A62 + "!#$%", 12); return "password=" + p, [p]
@shape("password_quoted", safe=False)
def _(r):
    p = rs(r, A62, 12); return 'pwd = "%s"' % p, [p]
@shape("bearer", safe=False)
def _(r):
    s = rs(r, B64U, 40); return "Authorization: Bearer " + s, [s]
@shape("basic", safe=False)
def _(r):
    s = b64_of(r, 18, slash=False); return "Authorization: Basic " + s, [s]
@shape("mysql_p", safe=False)
def _(r):
    p = rs(r, A62, 12); return "mysql -u root -p%s db" % p, [p]
@shape("sshpass", safe=False)
def _(r):
    p = rs(r, A62, 12); return "sshpass -p %s ssh host" % p, [p]
@shape("sas_sig", safe=False)
def _(r):
    s = b64_of(r, 32, slash=False).replace("+", "%2B").replace("=", "%3D"); return "https://acct.blob.core.windows.net/c/f?sv=2022-11-02&sig=" + s, [s[:30]]
@shape("recovery_dash")
def _(r):
    g = "-".join(rs(r, string.digits, 6) for _ in range(8)); return g, [g]
@shape("recovery_plain")
def _(r):
    s = rs(r, string.digits, 48); return s, [s]

# ---- the families and encodings a deny-list that names only the first group prints whole -------------------------------
@shape("glpat", group="unlisted")
def _(r):
    s = rs(r, B64U, 20); return "glpat-" + s, [s]
@shape("sk_live", group="unlisted")
def _(r):
    s = rs(r, A62, 24); return "sk_live_" + s, [s]
@shape("rk_live", group="unlisted")
def _(r):
    s = rs(r, A62, 24); return "rk_live_" + s, [s]
@shape("aiza", group="unlisted")
def _(r):
    s = rs(r, B64U, 35); return "AIza" + s, [s]
@shape("npm", group="unlisted")
def _(r):
    s = rs(r, A62, 36); return "npm_" + s, [s]
@shape("sendgrid", group="unlisted")
def _(r):
    a, b = rs(r, B64U, 22), rs(r, B64U, 43); return "SG.%s.%s" % (a, b), [a, b]
@shape("ya29", group="unlisted")
def _(r):
    s = rs(r, B64U, 100); return "ya29." + s, [s[:60]]
@shape("dop_v1", group="unlisted")
def _(r):
    s = rs(r, HEX, 64); return "dop_v1_" + s, [s]
@shape("twilio_sk", group="unlisted")
def _(r):
    s = rs(r, HEX, 32); return "SK" + s, [s]
@shape("aws_secret_slashed", group="unlisted")
def _(r):
    while True:
        s = rs(r, A62 + "/+", 40)
        if "/" in s:
            return s, [s]
@shape("aws_secret_plain", group="unlisted")
def _(r):
    s = rs(r, A62, 40); return s, [s]
@shape("b64_16_bytes", group="unlisted")
def _(r):
    s = b64_of(r, 16); return s, [s[:22]]
@shape("b64_20_bytes", group="unlisted")
def _(r):
    s = b64_of(r, 20); return s, [s[:27]]
@shape("b64_32_bytes", group="unlisted")
def _(r):
    s = b64_of(r, 32); return s, [s[:43]]
@shape("b64_48_bytes", group="unlisted")
def _(r):
    s = b64_of(r, 48); return s, [s]
@shape("b64_storage_key", group="unlisted")
def _(r):
    s = b64_of(r, 64); return s, [s[:86]]
@shape("base62_20", group="unlisted")
def _(r):
    s = rs(r, A62, 20); return s, [s]
@shape("base62_32", group="unlisted")
def _(r):
    s = rs(r, A62, 32); return s, [s]
@shape("lower_akia", group="unlisted")
def _(r):
    s = rs(r, LOW36, 16); return "akia" + s, [s]
@shape("upper_ghp", group="unlisted")
def _(r):
    s = rs(r, A62, 36).upper(); return "GHP_" + s, [s]
@shape("fullwidth_akia", group="unlisted")
def _(r):
    t, c = "AKIA" + rs(r, UP36, 16), None
    return "".join(chr(ord(ch) + 0xFEE0) if "!" <= ch <= "~" else ch for ch in t), [t[4:]]
@shape("ghp_zero_width_split", group="unlisted")
def _(r):
    s = rs(r, A62, 36); k = r.randrange(6, 36); return "ghp_" + s[:k] + "​" + s[k:], [s]
@shape("akia_nul_split", safe=False, group="unlisted")
def _(r):
    s = rs(r, UP36, 16); k = r.randrange(2, 14); return "AKIA" + s[:k] + "\x00" + s[k:], [s]
@shape("ghp_bidi_isolate_split", group="unlisted")
def _(r):
    s = rs(r, A62, 36); k = r.randrange(6, 36); return "ghp_" + s[:k] + "⁦" + s[k:], [s]
@shape("ghp_utf16le_in_8_bit", safe=False, group="unlisted")
def _(r):
    s = rs(r, A62, 36); return "".join(ch + "\x00" for ch in "ghp_" + s), [s]
@shape("db_password_named", safe=False, group="unlisted")
def _(r):
    p = rs(r, A62, 14); return "DB_PASSWORD=" + p, [p]
@shape("mysql_pwd_named", safe=False, group="unlisted")
def _(r):
    p = rs(r, A62, 14); return "MYSQL_PWD=" + p, [p]
@shape("github_token_named", safe=False, group="unlisted")
def _(r):
    p = rs(r, A62, 20); return "export GITHUB_TOKEN=" + p, [p]
@shape("camel_password_named", safe=False, group="unlisted")
def _(r):
    p = rs(r, A62, 14); return "adminPassword=" + p, [p]
@shape("password_colon", safe=False, group="unlisted")
def _(r):
    p = rs(r, A62, 14); return "password: " + p, [p]
@shape("json_password", safe=False, group="unlisted")
def _(r):
    p = rs(r, A62, 14); return '{"password": "%s"}' % p, [p]
@shape("long_option_password", safe=False, group="unlisted")
def _(r):
    p = rs(r, A62, 14); return "tool --password %s --next" % p, [p]
@shape("curl_user", safe=False, group="unlisted")
def _(r):
    p = rs(r, A62, 14); return "curl -u admin:%s https://h.example.test/" % p, [p]
@shape("cookie_header", safe=False, group="unlisted")
def _(r):
    p = rs(r, A62, 24); return "Cookie: session=" + p, [p]

@shape("base36_lower_32", group="unlisted")
def _(r):
    s = rs(r, LOW36, 32); return s, [s]
@shape("base36_upper_24", group="unlisted")
def _(r):
    s = rs(r, UP36, 24); return s, [s]
@shape("lower_letters_24", group="residual")
def _(r):
    s = rs(r, string.ascii_lowercase, 24); return s, [s]
@shape("base32_16", group="residual")
def _(r):
    s = rs(r, string.ascii_uppercase + "234567", 16); return s, [s]

# ---- shapes no rule here claims; a test asserts they are printed ------------------------------------------------------
@shape("plain_password_alone", group="residual")
def _(r):
    p = r.choice(["Summer", "Winter", "Dragon", "Monkey", "Shadow"]) + rs(r, string.digits, 6) + r.choice("!#$"); return p, [p]
@shape("passphrase_alone", group="residual")
def _(r):
    w = ["correct", "horse", "battery", "staple", "garden", "lantern", "marble", "violet"]
    p = "-".join(r.choice(w) for _ in range(4)); return p, [p]
@shape("short_random_12", group="residual")
def _(r):
    p = rs(r, A62, 12); return p, [p]
@shape("uuid_secret", group="residual")
def _(r):
    h = rs(r, HEX, 32); p = "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:]); return p, [p]


def names(groups=("listed",), safe_only=False):
    return [n for n, (fn, s, g) in SHAPES.items() if g in groups and (s or not safe_only)]


def make(name, rng):
    return SHAPES[name][0](rng)
`;

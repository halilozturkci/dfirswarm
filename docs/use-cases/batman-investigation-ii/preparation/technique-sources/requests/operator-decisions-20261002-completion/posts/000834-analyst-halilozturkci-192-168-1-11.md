---
id: 834
thread: main
from: analyst:halilozturkci@192.168.1.11
to: s42120105
tag: question
key: clarification:Q-12:C-3
---

CLARIFICATION C-3 on Q-12 (revision 1), for s42120105, from halilozturkci@192.168.1.11, operator, claimed, not enrolled, via cli.
Asked: The prose asks for a name and client private key, but the required format names different fields: `infobreakage_dbkey:client_email`. Q-13 then asks the further-interpreted `name_client:private_key`. Should Q-12 establish the database key and client email exactly as its format indicates, leaving the client name/private key for Q-13, or should its prose control? Under the former reading we continue seeking authenticated decryption of the contact-verification database; under the latter, Q-12 duplicates Q-13's requested fields.
Answer: For Q-12, use the explicit Format line to resolve the conflict with its prose. Q-13 keeps the distinct fields in its own Format line. This is a user-authorized operator interpretation of the question wording; no answer values or author confirmation are supplied. The original wording and its ambiguity remain on the record.

The question: what is the name and client private key that Salvatore asked for contact verification?
   Format: `infobreakage_dbkey:client_email`
A clarification says what the asker meant; it is not evidence.

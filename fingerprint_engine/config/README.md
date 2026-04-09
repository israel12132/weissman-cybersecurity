# Fuzzer payload signature config

`payload_signatures.json` defines **payload → expected_signature** rules for the dynamic signature engine.

- **payload**: Substring that identifies this attack (e.g. `"../../../etc/passwd"`, `"' OR 1=1 --"`). The fuzzer payload is matched if it contains this string (or the rule payload contains the fuzzer payload).
- **expected_signature**: Regex or literal string that **must** appear in the response body to consider the attack successful. If the response does not match, the finding is discarded (no false positive).

You can add more entries to scale to hundreds of vulnerability types. The engine loads this file from (in order):

1. Path in `WEISSMAN_PAYLOAD_SIGNATURES` env var  
2. `config/payload_signatures.json` relative to current dir or binary  
3. Embedded defaults if no file found  

Example new rule:

```json
{
  "payload": "UNION SELECT",
  "expected_signature": "syntax error|mysql_fetch|ORA-|pg_query"
}
```

# The bank's HTTP API through Warden

## What it does

The `teller` role reaches the playground bank's HTTP API for **your own
account**: check the balance, deposit, and withdraw. Warden authenticates
you, gets the bank a token of its own for each call, and injects it. You
never hold the bank's credential.

## How to call it

Take the role's `url` from `list_roles` and prepend `$WARDEN_ADDR`. Send your
own identity on every call as `Authorization: Bearer <your JWT>`, and send
request bodies as `Content-Type: application/json`.

```
URL      : $WARDEN_ADDR<url><route>
Identity : Authorization: Bearer <your JWT>
```

## Routes

| Route | Body | Does |
|---|---|---|
| `GET accounts/me` | none | returns your balance |
| `POST accounts/me/deposit` | `{"amount": <n>}` | adds `n` |
| `POST accounts/me/withdraw` | `{"amount": <n>}` | takes out `n` |

`n` is a whole number. Every answer is JSON: what the bank did under
`result`, and the decoded payload of the token Warden injected under
`access_token`.

**Show the token with every answer.** This bank is a teaching fixture, and
the token it received is the lesson: tell the user its `iss`, `aud`, `sub`,
`act` (when present) and `exp` alongside what the bank did. It is not the
token you sent.

## Examples

```bash
curl -s "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me" \
  -H "Authorization: Bearer $AGENT"

curl -s -X POST "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me/deposit" \
  -H "Authorization: Bearer $AGENT" -H "Content-Type: application/json" \
  -d '{"amount": 30}'

curl -s -X POST "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me/withdraw" \
  -H "Authorization: Bearer $AGENT" -H "Content-Type: application/json" \
  -d '{"amount": 50}'
```

## Quirks

- **A withdrawal over 100 is refused by Warden** with `403`, before the bank
  sees it: the role's policy reads the body's `amount`.
- **An overdraft is refused by the bank** with `409`: that is the bank's own
  rule, not Warden's.
- **Always send the JSON content type.** A body Warden cannot read has no
  `amount` for the policy to check, so a withdrawal without it is refused.

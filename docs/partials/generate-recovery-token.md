In the event that you lose access to the console via delegated access (the policy defined in Pomerium), there exists a fallback procedure to regain access to the console via a generated recovery token.

![Pomerium Enterprise Recovery Sign In](./img/recovery-token.png)

To generate a token, run the `pomerium-console generate-recovery token` command with the following flags:

| Flag                        | Description |
| --------------------------- | ----------- |
| `--database-encryption-key` | base64-encoded encryption key for encrypting sensitive data in the database. |
| `--database-url`            | The database to connect to (default "`postgresql://pomerium:pomerium@localhost:5432/dashboard?sslmode=disable`"). |
| `--namespace`               | The namespace to use (default "`9d8dbd2c-8cce-4e66-9c1f-c490b4a07243`" for Global). |
| `--out`                     | Where to save the JWT. If not specified, it will be printed to stdout. |
| `--ttl`                     | The amount of time before the recovery token expires. Requires a unit (example: `30s`, `5m`).|

::: tip
You can run the `pomerium-console` binary from any device with access to the database.
:::

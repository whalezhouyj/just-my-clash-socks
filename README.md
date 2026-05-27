# just-my-clash-socks

Convert [Just My Socks](https://justmysocks.net) subscriptions to Clash-compatible config.

## Usage

```
GET /api/sub?service={service}&id={id}
```

| Parameter | Required | Description |
| --- | --- | --- |
| `service` | Yes | JMS service ID |
| `id` | Yes | JMS subscription ID |
| `format` | No | Output format: `raw` (default YAML), `base64`, `uri` |

### Example

```
http://localhost:3456/api/sub?service={service}&id={id}
```

## Local Dev

```bash
npm install
npm start
```

Visit `http://localhost:3456/api/sub?service={service}&id={id}`

## Deploy

```bash
npx vercel --prod
```

## License

MIT

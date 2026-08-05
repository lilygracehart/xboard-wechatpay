# XBoard WeChat Pay Native API v3 Plugin

A WeChat Pay Native API v3 plugin for XBoard. The current implementation targets direct ordinary merchants and includes Native prepayment, API v3 request signing, response and callback verification, AES-256-GCM callback decryption, and merchant/order amount validation.

## Installation

Package this directory as a ZIP file, then upload, install, and enable it from the XBoard plugin manager. The plugin code is `wechatpay`, and the installed directory should be `plugins/Wechatpay`.

## Configuration

- An APPID bound to the merchant account
- Ordinary merchant ID (`mchid`)
- Merchant API certificate serial number
- Merchant API certificate private key from `apiclient_key.pem`
- 32-byte API v3 key
- WeChat Pay public key ID beginning with `PUB_KEY_ID_`
- WeChat Pay public key
- Optional product description

The asynchronous notification URL shown in the XBoard admin panel must be publicly reachable over HTTPS. Any reverse proxy or CDN must preserve the `Wechatpay-*` request headers. The plugin returns the official `code_url`, which XBoard renders with its existing QR-code component.

## Security

Keep the merchant private key and API v3 key only in the server-side payment configuration. Never place them in logs, client-side code, or public repositories. An order is marked as paid only after callback signature verification, decryption, merchant identity validation, and order amount validation all succeed.

> This PHP implementation is based on the official WeChat Pay API v3 documentation. It is a reference implementation and is not officially maintained by WeChat Pay. Review the code and complete end-to-end testing with real merchant credentials before production use.

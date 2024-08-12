# OASIS API for Javascript, typed

A simple ES5 library to interact with the OASIS API.

## Package

This package can be installed from NPM as

```
@nimiq/oasis-api
```

https://www.npmjs.com/package/@nimiq/oasis-api

## API

```ts
async function createHtlc(
    API_URL: string,
    contract: {
        asset: Asset,
        amount: number,
        beneficiary: OctetKeyPair | EllipticCurveKey,
        hash: {
            algorithm: 'sha256' | 'blake2b',
            value: string,
        },
        preimage: {
            size: 32,
        },
        expires: number,
        includeFee: boolean,
    },
    authorizationToken?: string,
): Promise<Htlc<HtlcStatus.PENDING>>
```

```ts
async function getHtlc(API_URL: string, id: string): Promise<Htlc>
```

```ts
async function settleHtlc(
    API_URL: string,
    id: string,
    secret: string,
    settlementJWS: string,
    authorizationToken?: string,
): Promise<Htlc<HtlcStatus.SETTLED>>
```

```ts
async function sandboxMockClearHtlc(API_URL: string, id: string): Promise<boolean>
```

```ts
async function exchangeAuthorizationToken(API_URL: string, token: string): Promise<string>
```

## Helper methods

```ts
function base64ToHex(base64: string): string
```

```ts
function hexToBase64(hex: string): string
```

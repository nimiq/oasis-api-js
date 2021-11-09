# OASIS API for Javascript, typed

A simple ES5 library to interact with the OASIS API.

## API

```ts
function init(url: string)
```

```ts
async function createHtlc(contract: {
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
}): Promise<Htlc<HtlcStatus.PENDING>>
```

```ts
async function getHtlc(id: string): Promise<Htlc>
```

```ts
async function settleHtlc(
    id: string,
    secret: string,
    settlementJWS: string,
): Promise<Htlc<HtlcStatus.SETTLED>>
```

```ts
async function sandboxMockClearHtlc(id: string): Promise<boolean>
```

## Helper methods

```ts
function base64ToHex(base64: string): string
```

```ts
function hexToBase64(hex: string): string
```

type OasisError = {
    type: string,
    title: string,
    status: number,
    detail?: string,
};

enum OasisAsset {
    EUR = 'eur',
    CRC = 'crc',
}

export enum Asset {
    EUR = 'EUR',
    CRC = 'CRC',
}

export enum HtlcStatus {
    PENDING = 'pending',
    CLEARED = 'cleared',
    SETTLED = 'settled',
    EXPIRED = 'expired',
}

export enum ClearingStatus {
    WAITING = 'waiting',
    PARTIAL = 'partial',
    DENIED = 'denied',
}

export enum SettlementStatus {
    WAITING = 'waiting',
    PENDING = 'pending',
    ACCEPTED = 'accepted',
    DENIED = 'denied',
    CONFIRMED = 'confirmed',
    FAILED = 'failed',
}

export enum DeniedReason {
    LIMIT_EXCEEDED = 'limit-exceeded',
}

export type CreationTokens = Partial<{
    authorization: string,
}>;

export enum TransactionType {
    SEPA = 'sepa',
    SINPEMOVIL = 'sinpemovil',
    MOCK = 'mock', // Only available in Sandbox environment
}

export type SepaRecipient = {
    iban: string,
    name: string,
    bic: string,
};

export type SepaClearingInstruction = {
    type: TransactionType.SEPA,
    amount: number,
    recipient: SepaRecipient,
    purpose?: string,
};

export type SinpeMovilClearingInstruction = {
    type: TransactionType.SINPEMOVIL,
    amount: number,
    phoneNumber: string,
    purpose?: string,
};

export type MockClearingInstruction = {
    type: TransactionType.MOCK,
    description: string,
};

export type ClearingInstruction = SepaClearingInstruction | SinpeMovilClearingInstruction | MockClearingInstruction;

export type ClearingInfo<CStatus = ClearingStatus> = {
    status: CStatus,
    type?: TransactionType,
    options: ClearingInstruction[],
    detail: CStatus extends ClearingStatus.PARTIAL ? {
            amount: number,
        }
        : CStatus extends ClearingStatus.DENIED ? {
                reason: DeniedReason,
            }
        : never,
};

export type SettlementInfo<SStatus = SettlementStatus> = {
    status: SStatus,
    type?: TransactionType,
    options: SStatus extends SettlementStatus.WAITING | SettlementStatus.DENIED | SettlementStatus.FAILED
        ? SettlementDescriptor[]
        : never,
    detail: SStatus extends SettlementStatus.DENIED | SettlementStatus.FAILED ? {
            reason: SStatus extends SettlementStatus.DENIED ? DeniedReason : string,
        }
        : SStatus extends SettlementStatus.ACCEPTED ? {
                eta?: string,
            }
        : never,
};

export type SettlementDescriptor = {
    type: TransactionType,
};

export type SepaSettlementInstruction = {
    type: TransactionType.SEPA,
    contractId: string,
    recipient: SepaRecipient,
};

export type SinpeMovilSettlementInstruction = {
    type: TransactionType.SINPEMOVIL,
    contractId: string,
    phoneNumber: string,
};

export type MockSettlementInstruction = {
    type: TransactionType.MOCK,
    contractId: string,
};

export type SettlementInstruction =
    | SepaSettlementInstruction
    | SinpeMovilSettlementInstruction
    | MockSettlementInstruction;

export type SettlementTokens = Partial<{
    authorization: string,
    smsApi: string,
}>;

export enum KeyType {
    OCTET_KEY_PAIR = 'OKP',
    ELLIPTIC_CURVE = 'EC',
}

export enum OctetKeyCurve {
    ED25519 = 'ed25519',
}

export enum EllipticKeyCurve {
    P256 = 'p-256',
    P256K = 'p-256k',
}

export type OctetKeyPair = {
    kty: KeyType.OCTET_KEY_PAIR,
    crv: OctetKeyCurve,
    x: string,
};

export type EllipticCurveKey = {
    kty: KeyType.ELLIPTIC_CURVE,
    crv: EllipticKeyCurve,
    x: string,
    y: string,
};

export type Htlc<TStatus = HtlcStatus> = {
    id: string,
    status: TStatus,
    asset: Asset,
    amount: number,
    fee: number,
    beneficiary: OctetKeyPair | EllipticCurveKey,
    hash: {
        algorithm: 'sha256' | 'blake2b', // 'sha512' excluded for now, as it requires a different preimage size
        value: string,
    },
    preimage: {
        size: 32,
        value: TStatus extends HtlcStatus.SETTLED ? string : never,
    },
    expires: number,
    clearing: TStatus extends HtlcStatus.PENDING ? ClearingInfo : never,
    settlement: TStatus extends HtlcStatus.CLEARED | HtlcStatus.SETTLED ? SettlementInfo : never,
};

export type RawHtlc<TStatus = HtlcStatus> = Omit<Htlc<TStatus>, 'asset' | 'expires'> & {
    asset: OasisAsset,
    expires: string,
};

async function api<T>(
    API_URL: string,
    path: string,
    method: 'POST' | 'GET' | 'DELETE',
    body?: Record<string, unknown>,
    headers?: Record<string, string>,
): Promise<T> {
    if (!API_URL) throw new Error('API URL not set, call init() first');

    const response = await fetch(`${API_URL}${path}`, {
        method,
        headers: {
            'Content-Type': 'application/json',
            ...headers,
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
    });

    if (!response.ok) {
        const error = await response.json() as OasisError;
        throw new Error(`${error.title}${error.detail ? `: ${error.detail}` : ''}`);
    }
    return response.json();
}

export async function createHtlc(
    API_URL: string,
    contract: Pick<RawHtlc, 'asset' | 'amount' | 'beneficiary' | 'hash' | 'preimage' | 'expires'> & {
        includeFee: boolean,
    },
    tokens?: CreationTokens,
): Promise<Htlc<HtlcStatus.PENDING>> {
    if (contract.beneficiary.kty === KeyType.OCTET_KEY_PAIR || contract.beneficiary.kty === KeyType.ELLIPTIC_CURVE) {
        const { x } = contract.beneficiary;
        if (x.length === 64) {
            contract.beneficiary.x = hexToBase64(x);
        } else if (fromBase64Url(x).length !== 32) {
            throw new Error('Beneficiary x must be in HEX or Base64Url format');
        }
        while (contract.beneficiary.x.slice(-1) === '.') {
            contract.beneficiary.x = contract.beneficiary.x.slice(0, -1);
        }
    }

    if (contract.beneficiary.kty === KeyType.ELLIPTIC_CURVE) {
        const { y } = contract.beneficiary;
        if (y.length === 64) {
            contract.beneficiary.y = hexToBase64(y);
        } else if (fromBase64Url(y).length !== 32) {
            throw new Error('Beneficiary y must be in HEX or Base64Url format');
        }
        while (contract.beneficiary.y.slice(-1) === '.') {
            contract.beneficiary.y = contract.beneficiary.y.slice(0, -1);
        }
    }

    if (contract.hash.value.length === 64) {
        contract.hash.value = hexToBase64(contract.hash.value);
    } else if (fromBase64Url(contract.hash.value).length !== 32) {
        throw new Error('Hash value must be in HEX or Base64Url format');
    }
    while (contract.hash.value.slice(-1) === '.') {
        contract.hash.value = contract.hash.value.slice(0, -1);
    }

    if (typeof contract.expires === 'number') {
        const expires = contract.expires * (contract.expires < 1e12 ? 1000 : 1);
        contract.expires = new Date(expires).toISOString();
    }

    const headers: Record<string, string> = {};
    if (tokens?.authorization) {
        headers['Authorization'] = `Bearer ${tokens.authorization}`;
    }

    const htlc = await api<RawHtlc<HtlcStatus.PENDING>>(
        API_URL,
        '/htlc',
        'POST',
        contract,
        headers,
    );
    return convertHtlc(htlc);
}

export async function getHtlc(API_URL: string, id: string): Promise<Htlc> {
    const htlc = await api<RawHtlc<HtlcStatus>>(API_URL, `/htlc/${id}`, 'GET');
    return convertHtlc(htlc);
}

export async function settleHtlc(
    API_URL: string,
    id: string,
    secret: string,
    settlementJWS: string,
    tokens?: SettlementTokens,
): Promise<Htlc<HtlcStatus.SETTLED>> {
    if (secret.length === 64) {
        secret = hexToBase64(secret);
    } else if (fromBase64Url(secret).length !== 32) {
        throw new Error('Secret must be in HEX or Base64Url format');
    }
    while (secret.slice(-1) === '.') {
        secret = secret.slice(0, -1);
    }

    if ((settlementJWS.split('.') || []).length !== 3) {
        throw new Error('Invalid settlement instruction JWS');
    }

    const headers: Record<string, string> = {};
    if (tokens?.authorization) {
        headers['Authorization'] = `Bearer ${tokens.authorization}`;
    }
    if (tokens?.smsApi) {
        headers['X-SMS-API-Token'] = tokens.smsApi;
    }

    const htlc = await api<RawHtlc<HtlcStatus.SETTLED>>(
        API_URL,
        `/htlc/${id}/settle`,
        'POST',
        {
            preimage: secret,
            settlement: settlementJWS,
        },
        headers,
    );
    return convertHtlc(htlc);
}

export async function sandboxMockClearHtlc(API_URL: string, id: string): Promise<boolean> {
    if (!API_URL) throw new Error('API URL not set, call init() first');

    return fetch(`${API_URL}/mock/clear/${id}`, {
        method: 'POST',
        mode: 'no-cors',
    }).then(async (res) => {
        if (!res.ok) {
            throw new Error('Mock-clearing failed');
        }
        return true;
    });
}

export async function exchangeAuthorizationToken(API_URL: string, token: string): Promise<string> {
    const response = await api<{ token: string }>(API_URL, '/auth', 'POST', undefined, {
        'Authorization': `Bearer ${token}`,
    });
    return response.token;
}

function convertHtlc<TStatus extends HtlcStatus>(htlc: RawHtlc<TStatus>): Htlc<TStatus> {
    const contract: Htlc<TStatus> = {
        id: htlc.id,
        status: htlc.status,
        asset: htlc.asset.toUpperCase() as Asset,
        amount: coinsToUnits(htlc.asset, htlc.amount),
        fee: coinsToUnits(htlc.asset, htlc.fee, true),
        beneficiary: htlc.beneficiary.kty === KeyType.ELLIPTIC_CURVE
            ? {
                ...htlc.beneficiary,
                crv: htlc.beneficiary.crv.toLowerCase() as EllipticKeyCurve,
                x: base64ToHex(htlc.beneficiary.x),
                y: base64ToHex(htlc.beneficiary.y),
            }
            : {
                ...htlc.beneficiary,
                crv: htlc.beneficiary.crv.toLowerCase() as OctetKeyCurve,
                x: base64ToHex(htlc.beneficiary.x),
            },
        hash: {
            ...htlc.hash,
            value: base64ToHex(htlc.hash.value),
        },
        // @ts-expect-error Type string is not assignable to type TStatus extends HtlcStatus.SETTLED ? string : never
        preimage: {
            ...htlc.preimage,
            ...('value' in htlc.preimage
                ? {
                    value: base64ToHex((htlc as unknown as RawHtlc<HtlcStatus.SETTLED>).preimage.value),
                }
                : {}),
        },
        expires: Math.floor(Date.parse(htlc.expires) / 1000),
        ...('clearing' in htlc
            ? {
                clearing: {
                    ...htlc.clearing,
                    options: htlc.clearing.options.map((instructions) => ({
                        ...instructions,
                        ...('amount' in instructions
                            ? {
                                amount: coinsToUnits(htlc.asset, instructions.amount),
                            }
                            : {}),
                    })),
                    ...(htlc.clearing.status === ClearingStatus.PARTIAL
                        ? {
                            detail: {
                                amount: coinsToUnits(
                                    htlc.asset,
                                    (htlc.clearing as ClearingInfo<ClearingStatus.PARTIAL>).detail.amount,
                                ),
                            },
                        }
                        : {}),
                },
            }
            : {}),
        ...('settlement' in htlc
            ? {
                settlement: htlc.settlement,
            }
            : {}),
    };

    return contract;
}

function coinsToUnits(asset: OasisAsset, value: string | number, roundUp = false): number {
    let decimals: number;
    switch (asset) {
        case OasisAsset.EUR:
        case OasisAsset.CRC:
            decimals = 2;
            break;
        default:
            throw new Error(`Invalid asset ${asset}`);
    }
    const parts = value.toString().split('.');
    parts[1] = (parts[1] || '').substring(0, decimals + 1);
    while (parts[1].length < decimals + 1) {
        parts[1] += '0';
    }
    const units = parseInt(parts.join(''), 10) / 10;

    if (roundUp) {
        return Math.ceil(units);
    }

    return Math.floor(units);
}

export function base64ToHex(base64: string): string {
    return toHex(fromBase64Url(base64));
}

export function hexToBase64(hex: string): string {
    return toBase64Url(fromHex(hex));
}

function fromBase64Url(base64: string): Uint8Array {
    base64 = base64.replace(/_/g, '/').replace(/-/g, '+').replace(/\./g, '=');
    return new Uint8Array(atob(base64).split('').map((c) => c.charCodeAt(0)));
}

function toBase64Url(buffer: Uint8Array): string {
    let byteString = '';
    for (let i = 0; i < buffer.length; i++) {
        const code = buffer[i];
        byteString += String.fromCharCode(code);
    }
    return btoa(byteString).replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');
}

function fromHex(hex: string): Uint8Array {
    return new Uint8Array((hex.trim().match(/.{2}/g) || []).map((byte) => parseInt(byte, 16)));
}

function toHex(buffer: Uint8Array): string {
    const HEX_ALPHABET = '0123456789abcdef';
    let hex = '';
    for (let i = 0; i < buffer.length; i++) {
        const code = buffer[i];
        hex += HEX_ALPHABET[code >>> 4]; // eslint-disable-line no-bitwise
        hex += HEX_ALPHABET[code & 0x0F]; // eslint-disable-line no-bitwise
    }
    return hex;
}

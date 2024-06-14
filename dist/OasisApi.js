var OasisAsset;
(function (OasisAsset) {
    OasisAsset["EUR"] = "eur";
    OasisAsset["CRC"] = "crc";
})(OasisAsset || (OasisAsset = {}));
export var Asset;
(function (Asset) {
    Asset["EUR"] = "EUR";
    Asset["CRC"] = "CRC";
})(Asset || (Asset = {}));
export var HtlcStatus;
(function (HtlcStatus) {
    HtlcStatus["PENDING"] = "pending";
    HtlcStatus["CLEARED"] = "cleared";
    HtlcStatus["SETTLED"] = "settled";
    HtlcStatus["EXPIRED"] = "expired";
})(HtlcStatus || (HtlcStatus = {}));
export var ClearingStatus;
(function (ClearingStatus) {
    ClearingStatus["WAITING"] = "waiting";
    ClearingStatus["PARTIAL"] = "partial";
    ClearingStatus["DENIED"] = "denied";
})(ClearingStatus || (ClearingStatus = {}));
export var SettlementStatus;
(function (SettlementStatus) {
    SettlementStatus["WAITING"] = "waiting";
    SettlementStatus["PENDING"] = "pending";
    SettlementStatus["ACCEPTED"] = "accepted";
    SettlementStatus["DENIED"] = "denied";
    SettlementStatus["CONFIRMED"] = "confirmed";
    SettlementStatus["FAILED"] = "failed";
})(SettlementStatus || (SettlementStatus = {}));
export var DeniedReason;
(function (DeniedReason) {
    DeniedReason["LIMIT_EXCEEDED"] = "limit-exceeded";
})(DeniedReason || (DeniedReason = {}));
export var TransactionType;
(function (TransactionType) {
    TransactionType["SEPA"] = "sepa";
    TransactionType["SINPEMOVIL"] = "sinpemovil";
    TransactionType["MOCK"] = "mock";
})(TransactionType || (TransactionType = {}));
export var KeyType;
(function (KeyType) {
    KeyType["OCTET_KEY_PAIR"] = "OKP";
    KeyType["ELLIPTIC_CURVE"] = "EC";
})(KeyType || (KeyType = {}));
export var OctetKeyCurve;
(function (OctetKeyCurve) {
    OctetKeyCurve["ED25519"] = "ed25519";
})(OctetKeyCurve || (OctetKeyCurve = {}));
export var EllipticKeyCurve;
(function (EllipticKeyCurve) {
    EllipticKeyCurve["P256"] = "p-256";
    EllipticKeyCurve["P256K"] = "p-256k";
})(EllipticKeyCurve || (EllipticKeyCurve = {}));
async function api(API_URL, path, method, body, headers) {
    if (!API_URL)
        throw new Error('API URL not set, call init() first');
    const response = await fetch(`${API_URL}${path}`, Object.assign({ method, headers: Object.assign({ 'Content-Type': 'application/json' }, headers) }, (body ? { body: JSON.stringify(body) } : {})));
    if (!response.ok) {
        const error = await response.json();
        throw new Error(`${error.title}${error.detail ? `: ${error.detail}` : ''}`);
    }
    return response.json();
}
export async function createHtlc(API_URL, contract, tokens) {
    if (contract.beneficiary.kty === KeyType.OCTET_KEY_PAIR || contract.beneficiary.kty === KeyType.ELLIPTIC_CURVE) {
        const { x } = contract.beneficiary;
        if (x.length === 64) {
            contract.beneficiary.x = hexToBase64(x);
        }
        else if (fromBase64Url(x).length !== 32) {
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
        }
        else if (fromBase64Url(y).length !== 32) {
            throw new Error('Beneficiary y must be in HEX or Base64Url format');
        }
        while (contract.beneficiary.y.slice(-1) === '.') {
            contract.beneficiary.y = contract.beneficiary.y.slice(0, -1);
        }
    }
    if (contract.hash.value.length === 64) {
        contract.hash.value = hexToBase64(contract.hash.value);
    }
    else if (fromBase64Url(contract.hash.value).length !== 32) {
        throw new Error('Hash value must be in HEX or Base64Url format');
    }
    while (contract.hash.value.slice(-1) === '.') {
        contract.hash.value = contract.hash.value.slice(0, -1);
    }
    if (typeof contract.expires === 'number') {
        const expires = contract.expires * (contract.expires < 1e12 ? 1000 : 1);
        contract.expires = new Date(expires).toISOString();
    }
    const headers = {};
    if (tokens === null || tokens === void 0 ? void 0 : tokens.authorization) {
        headers['Authorization'] = `Bearer ${tokens.authorization}`;
    }
    const htlc = await api(API_URL, '/htlc', 'POST', contract, headers);
    return convertHtlc(htlc);
}
export async function getHtlc(API_URL, id) {
    const htlc = await api(API_URL, `/htlc/${id}`, 'GET');
    return convertHtlc(htlc);
}
export async function settleHtlc(API_URL, id, secret, settlementJWS, tokens) {
    if (secret.length === 64) {
        secret = hexToBase64(secret);
    }
    else if (fromBase64Url(secret).length !== 32) {
        throw new Error('Secret must be in HEX or Base64Url format');
    }
    while (secret.slice(-1) === '.') {
        secret = secret.slice(0, -1);
    }
    if ((settlementJWS.split('.') || []).length !== 3) {
        throw new Error('Invalid settlement instruction JWS');
    }
    const headers = {};
    if (tokens === null || tokens === void 0 ? void 0 : tokens.authorization) {
        headers['Authorization'] = `Bearer ${tokens.authorization}`;
    }
    if (tokens === null || tokens === void 0 ? void 0 : tokens.smsApi) {
        headers['X-SMS-API-Token'] = tokens.smsApi;
    }
    const htlc = await api(API_URL, `/htlc/${id}/settle`, 'POST', {
        preimage: secret,
        settlement: settlementJWS,
    }, headers);
    return convertHtlc(htlc);
}
export async function sandboxMockClearHtlc(API_URL, id) {
    if (!API_URL)
        throw new Error('API URL not set, call init() first');
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
export async function exchangeAuthorizationToken(API_URL, token) {
    const response = await api(API_URL, '/auth', 'POST', undefined, {
        'Authorization': `Bearer ${token}`,
    });
    return response.token;
}
function convertHtlc(htlc) {
    const contract = Object.assign(Object.assign({ id: htlc.id, status: htlc.status, asset: htlc.asset.toUpperCase(), amount: coinsToUnits(htlc.asset, htlc.amount), fee: coinsToUnits(htlc.asset, htlc.fee, true), beneficiary: htlc.beneficiary.kty === KeyType.ELLIPTIC_CURVE
            ? Object.assign(Object.assign({}, htlc.beneficiary), { crv: htlc.beneficiary.crv.toLowerCase(), x: base64ToHex(htlc.beneficiary.x), y: base64ToHex(htlc.beneficiary.y) }) : Object.assign(Object.assign({}, htlc.beneficiary), { crv: htlc.beneficiary.crv.toLowerCase(), x: base64ToHex(htlc.beneficiary.x) }), hash: Object.assign(Object.assign({}, htlc.hash), { value: base64ToHex(htlc.hash.value) }), preimage: Object.assign(Object.assign({}, htlc.preimage), ('value' in htlc.preimage
            ? {
                value: base64ToHex(htlc.preimage.value),
            }
            : {})), expires: Math.floor(Date.parse(htlc.expires) / 1000) }, ('clearing' in htlc
        ? {
            clearing: Object.assign(Object.assign(Object.assign({}, htlc.clearing), { options: htlc.clearing.options.map((instructions) => (Object.assign(Object.assign({}, instructions), ('amount' in instructions
                    ? {
                        amount: coinsToUnits(htlc.asset, instructions.amount),
                    }
                    : {})))) }), (htlc.clearing.status === ClearingStatus.PARTIAL
                ? {
                    detail: {
                        amount: coinsToUnits(htlc.asset, htlc.clearing.detail.amount),
                    },
                }
                : {})),
        }
        : {})), ('settlement' in htlc
        ? {
            settlement: htlc.settlement,
        }
        : {}));
    return contract;
}
function coinsToUnits(asset, value, roundUp = false) {
    let decimals;
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
export function base64ToHex(base64) {
    return toHex(fromBase64Url(base64));
}
export function hexToBase64(hex) {
    return toBase64Url(fromHex(hex));
}
function fromBase64Url(base64) {
    base64 = base64.replace(/_/g, '/').replace(/-/g, '+').replace(/\./g, '=');
    return new Uint8Array(atob(base64).split('').map((c) => c.charCodeAt(0)));
}
function toBase64Url(buffer) {
    let byteString = '';
    for (let i = 0; i < buffer.length; i++) {
        const code = buffer[i];
        byteString += String.fromCharCode(code);
    }
    return btoa(byteString).replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');
}
function fromHex(hex) {
    return new Uint8Array((hex.trim().match(/.{2}/g) || []).map((byte) => parseInt(byte, 16)));
}
function toHex(buffer) {
    const HEX_ALPHABET = '0123456789abcdef';
    let hex = '';
    for (let i = 0; i < buffer.length; i++) {
        const code = buffer[i];
        hex += HEX_ALPHABET[code >>> 4];
        hex += HEX_ALPHABET[code & 0x0F];
    }
    return hex;
}

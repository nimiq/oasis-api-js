declare enum OasisAsset {
    EUR = "eur",
    CRC = "crc"
}
export declare enum Asset {
    EUR = "EUR",
    CRC = "CRC"
}
export declare enum HtlcStatus {
    PENDING = "pending",
    CLEARED = "cleared",
    SETTLED = "settled",
    EXPIRED = "expired"
}
export declare enum ClearingStatus {
    WAITING = "waiting",
    PARTIAL = "partial",
    DENIED = "denied"
}
export declare enum SettlementStatus {
    WAITING = "waiting",
    PENDING = "pending",
    ACCEPTED = "accepted",
    DENIED = "denied",
    CONFIRMED = "confirmed",
    FAILED = "failed"
}
export declare enum DeniedReason {
    LIMIT_EXCEEDED = "limit-exceeded"
}
export type CreationTokens = Partial<{
    authorization: string;
}>;
export declare enum TransactionType {
    SEPA = "sepa",
    SINPEMOVIL = "sinpemovil",
    MOCK = "mock"
}
export type SepaRecipient = {
    iban: string;
    name: string;
    bic: string;
};
export type SepaClearingInstruction = {
    type: TransactionType.SEPA;
    amount: number;
    recipient: SepaRecipient;
    purpose?: string;
};
export type SinpeMovilClearingInstruction = {
    type: TransactionType.SINPEMOVIL;
    amount: number;
    phoneNumber: string;
    purpose?: string;
};
export type MockClearingInstruction = {
    type: TransactionType.MOCK;
    description: string;
};
export type ClearingInstruction = SepaClearingInstruction | SinpeMovilClearingInstruction | MockClearingInstruction;
export type ClearingInfo<CStatus = ClearingStatus> = {
    status: CStatus;
    type?: TransactionType;
    options: ClearingInstruction[];
    detail: CStatus extends ClearingStatus.PARTIAL ? {
        amount: number;
    } : CStatus extends ClearingStatus.DENIED ? {
        reason: DeniedReason;
    } : never;
};
export type SettlementInfo<SStatus = SettlementStatus> = {
    status: SStatus;
    type?: TransactionType;
    options: SStatus extends SettlementStatus.WAITING | SettlementStatus.DENIED | SettlementStatus.FAILED ? SettlementDescriptor[] : never;
    detail: SStatus extends SettlementStatus.DENIED | SettlementStatus.FAILED ? {
        reason: SStatus extends SettlementStatus.DENIED ? DeniedReason : string;
    } : SStatus extends SettlementStatus.ACCEPTED ? {
        eta?: string;
    } : never;
};
export type SettlementDescriptor = {
    type: TransactionType;
};
export type SepaSettlementInstruction = {
    type: TransactionType.SEPA;
    contractId: string;
    recipient: SepaRecipient;
};
export type SinpeMovilSettlementInstruction = {
    type: TransactionType.SINPEMOVIL;
    contractId: string;
    phoneNumber: string;
};
export type MockSettlementInstruction = {
    type: TransactionType.MOCK;
    contractId: string;
};
export type SettlementInstruction = SepaSettlementInstruction | SinpeMovilSettlementInstruction | MockSettlementInstruction;
export type SettlementTokens = Partial<{
    authorization: string;
    smsApi: string;
}>;
export declare enum KeyType {
    OCTET_KEY_PAIR = "OKP",
    ELLIPTIC_CURVE = "EC"
}
export declare enum OctetKeyCurve {
    ED25519 = "ed25519"
}
export declare enum EllipticKeyCurve {
    P256 = "p-256",
    P256K = "p-256k"
}
export type OctetKeyPair = {
    kty: KeyType.OCTET_KEY_PAIR;
    crv: OctetKeyCurve;
    x: string;
};
export type EllipticCurveKey = {
    kty: KeyType.ELLIPTIC_CURVE;
    crv: EllipticKeyCurve;
    x: string;
    y: string;
};
export type Htlc<TStatus = HtlcStatus> = {
    id: string;
    status: TStatus;
    asset: Asset;
    amount: number;
    fee: number;
    beneficiary: OctetKeyPair | EllipticCurveKey;
    hash: {
        algorithm: 'sha256' | 'blake2b';
        value: string;
    };
    preimage: {
        size: 32;
        value: TStatus extends HtlcStatus.SETTLED ? string : never;
    };
    expires: number;
    clearing: TStatus extends HtlcStatus.PENDING ? ClearingInfo : never;
    settlement: TStatus extends HtlcStatus.CLEARED | HtlcStatus.SETTLED ? SettlementInfo : never;
};
export type RawHtlc<TStatus = HtlcStatus> = Omit<Htlc<TStatus>, 'asset' | 'expires'> & {
    asset: OasisAsset;
    expires: string;
};
export declare function createHtlc(API_URL: string, contract: Pick<RawHtlc, 'asset' | 'amount' | 'beneficiary' | 'hash' | 'preimage' | 'expires'> & {
    includeFee: boolean;
}, tokens?: CreationTokens): Promise<Htlc<HtlcStatus.PENDING>>;
export declare function getHtlc(API_URL: string, id: string): Promise<Htlc>;
export declare function settleHtlc(API_URL: string, id: string, secret: string, settlementJWS: string, tokens?: SettlementTokens): Promise<Htlc<HtlcStatus.SETTLED>>;
export declare function sandboxMockClearHtlc(API_URL: string, id: string): Promise<boolean>;
export declare function exchangeAuthorizationToken(API_URL: string, token: string): Promise<string>;
export declare function base64ToHex(base64: string): string;
export declare function hexToBase64(hex: string): string;
export {};

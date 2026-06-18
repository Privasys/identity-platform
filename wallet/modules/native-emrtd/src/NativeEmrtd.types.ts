// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/** MRZ-derived access key for the eMRTD secure channel (BAC/PACE). The MRZ
 *  itself is not sensitive; it is OCR'd or hand-entered to unlock the chip. */
export interface MrzKey {
    /** Passport/ID document number. */
    documentNumber: string;
    /** Date of birth, YYMMDD. */
    dateOfBirth: string;
    /** Date of expiry, YYMMDD. */
    dateOfExpiry: string;
}

/** Result of reading the eMRTD chip. The wallet forwards this to the verifier
 *  enclave (over RA-TLS) to derive the IVR; nothing is persisted unencrypted. */
export interface EmrtdReadResult {
    /** Parsed DG1 fields, normalised to canonical attribute keys:
     *  given_name, family_name, birthdate (YYYY-MM-DD), nationality
     *  (ISO 3166-1 alpha-3), document_number, document_type, expiry_date. */
    fields: Record<string, string>;
    /** DG2 portrait (base64; JPEG or JPEG2000), for the enclave face match. */
    portraitBase64?: string;
    /** EF.SOD (base64) — the signed Document Security Object the enclave uses
     *  for Passive Authentication (DSC→CSCA chain + DG hash integrity). */
    sodBase64?: string;
    /** Device-side preliminary Passive-Auth result (DG hashes ↔ SOD). The
     *  enclave re-verifies authoritatively; this is only a fast-fail hint. */
    passiveAuthHint?: boolean;
}

/** Whether eMRTD NFC reading is available on this device/build. */
export interface EmrtdSupport {
    supported: boolean;
    /** Human-readable reason when not supported. */
    reason?: string;
}

/** MRZ fields OCR'd from a photo of the document's machine-readable zone,
 *  ready to use as the chip access key (see MrzKey). */
export interface MrzScan {
    documentNumber: string;
    dateOfBirth: string;
    dateOfExpiry: string;
}

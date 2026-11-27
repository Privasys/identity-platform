// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

export { AuthFrame } from './client/auth-frame';
export { ConnectError, InsufficientCreditsError } from './client/types';
export type {
    AppChannel,
    AppResponse,
    AppStreamResponse,
    AppWebSocket,
    AttributeDisclosure,
    AuthFrameConfig,
    GateOutcome,
    Session,
} from './client/types';
export type { GateChoice, GateControls, GateOptions, GateState } from './gate-headless';
export type { AuthTheme } from './theme';
export {
    fetchAttributeReferential,
    isBillable,
    isGovVerified,
    marketplaceKeyOf,
    requestableAttributes,
} from './attributes';
export { CREDITS_PER_GBP, disclosureCost, formatCredits } from './attribute-pricing';
export type { CanonicalAttribute } from './attributes';
export type { AttributeSectionId } from './attribute-pricing';
export type { AttributeSectionCopy } from './attributes-ui';

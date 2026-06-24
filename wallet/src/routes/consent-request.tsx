// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Consent request screen — shown when an enclave app requests personal data.
 *
 * Triggered via push notification or deep link. Displays what data is being
 * requested, why, and the attestation state of the enclave. The user can
 * approve or deny each attribute individually and optionally set standing
 * consent for the app. Presentation is the shared DataRequestConsent component
 * (also used by the KYC identity-verification flow).
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useState, useMemo } from 'react';
import { StyleSheet, Pressable, View as RNView, Alert } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { DataRequestConsent, type ConsentDataItem } from '@/components/DataRequestConsent';
import { Text } from '@/components/Themed';
import { getAttributeValues, recordConsent } from '@/services/consent';
import type { DataRequest } from '@/services/consent';
import { deliverViaBroker } from '@/services/data-transit';

/** Friendly labels for attribute keys. */
const ATTRIBUTE_LABELS: Record<string, string> = {
    displayName: 'Display Name',
    email: 'Email Address',
    avatarUri: 'Profile Photo',
    locale: 'Language / Locale',
    did: 'Decentralised Identifier',
    sub: 'App-Specific Identifier'
};

function attributeLabel(key: string): string {
    return ATTRIBUTE_LABELS[key] ?? key;
}

export default function ConsentRequestScreen() {
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const params = useLocalSearchParams<{
        rpId: string;
        origin: string;
        appName?: string;
        sessionId: string;
        requestedAttributes: string;
        purpose?: string;
        teeType: string;
        enclaveMeasurement: string;
        codeHash: string;
    }>();

    const request: DataRequest = useMemo(
        () => ({
            rpId: params.rpId ?? '',
            origin: params.origin ?? '',
            appName: params.appName,
            sessionId: params.sessionId ?? '',
            requestedAttributes: params.requestedAttributes
                ? params.requestedAttributes.split(',')
                : [],
            purpose: params.purpose,
            teeType: (params.teeType as 'sgx' | 'tdx') ?? 'sgx',
            enclaveMeasurement: params.enclaveMeasurement ?? '',
            codeHash: params.codeHash ?? ''
        }),
        [params]
    );

    // Per-attribute toggle state — all start approved
    const [approvals, setApprovals] = useState<Record<string, boolean>>(() =>
        Object.fromEntries(request.requestedAttributes.map((k) => [k, true]))
    );

    const [persistent, setPersistent] = useState(false);
    const [submitting, setSubmitting] = useState(false);

    const approvedCount = Object.values(approvals).filter(Boolean).length;
    const totalCount = request.requestedAttributes.length;

    const attributeValues = useMemo(
        () => getAttributeValues(request.requestedAttributes),
        [request.requestedAttributes]
    );

    const toggleAttribute = (key: string) => {
        setApprovals((prev) => ({ ...prev, [key]: !prev[key] }));
    };

    const items: ConsentDataItem[] = request.requestedAttributes.map((key) => {
        const hasValue = key in attributeValues;
        return {
            key,
            label: attributeLabel(key),
            sublabel: hasValue ? attributeValues[key] : 'Not in your profile',
            missing: !hasValue,
            toggle: {
                value: !!approvals[key] && hasValue,
                onChange: () => toggleAttribute(key),
                disabled: !hasValue,
            },
        };
    });

    const handleApprove = async () => {
        const approved = Object.entries(approvals)
            .filter(([, v]) => v)
            .map(([k]) => k);

        if (approved.length === 0) {
            Alert.alert('No data selected', 'Select at least one attribute to share, or deny the request.');
            return;
        }

        setSubmitting(true);
        try {
            await recordConsent(request, approved, persistent);

            // Deliver approved data to the enclave via broker relay
            if (request.sessionId) {
                const brokerUrl = process.env['EXPO_PUBLIC_BROKER_WS_URL'] ?? '';
                if (brokerUrl) {
                    await deliverViaBroker(approved, {
                        brokerUrl,
                        sessionId: request.sessionId
                    }, request.rpId);
                }
            }

            router.back();
        } catch (e: any) {
            Alert.alert('Error', e.message);
        } finally {
            setSubmitting(false);
        }
    };

    const handleDeny = async () => {
        setSubmitting(true);
        try {
            await recordConsent(request, [], false);
            router.back();
        } catch {
            // Best effort
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <RNView style={styles.screen}>
            <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
                <Pressable onPress={() => router.back()} style={styles.closeButton}>
                    <Ionicons name="close" size={24} color="#FFFFFF" />
                </Pressable>
                <Text style={styles.headerTitle}>Data Request</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            <DataRequestConsent
                appName={request.appName ?? request.rpId}
                origin={request.origin}
                purpose={request.purpose}
                attestation={{
                    teeType: request.teeType,
                    measurement: request.enclaveMeasurement,
                    codeHash: request.codeHash,
                }}
                expandable
                sectionDescription={`Select which data to share with this app. ${approvedCount} of ${totalCount} selected.`}
                items={items}
                persistent={{ value: persistent, onChange: setPersistent }}
                approveLabel="Share"
                approveCount={approvedCount}
                approveDisabled={approvedCount === 0}
                submitting={submitting}
                onDeny={handleDeny}
                onApprove={handleApprove}
                actionsBottomInset={insets.bottom + 16}
            />
        </RNView>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 20,
        paddingBottom: 16,
        backgroundColor: '#0F172A'
    },
    closeButton: {
        width: 32,
        height: 32,
        borderRadius: 16,
        backgroundColor: 'rgba(255,255,255,0.12)',
        alignItems: 'center',
        justifyContent: 'center'
    },
    headerTitle: {
        fontSize: 18,
        fontWeight: '700',
        color: '#FFFFFF'
    }
});

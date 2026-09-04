// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The one place a recovery phrase is shown to its holder.
 *
 * Three screens hand out a phrase: Secure Wallet on first setup, Account
 * Recovery when it is regenerated, and Recover Account when a completed
 * recovery mints a replacement. They had three copies of this card, and the
 * newest of them had drifted: it offered Copy but not Share, so the phrase
 * issued at the end of a recovery, the single most important one the wallet
 * ever shows, was the one you could not print (found 2026-09-04).
 *
 * A phrase is shown ONCE. Whatever the holder cannot save in that moment is
 * gone, so the actions on this card are not a convenience and none of the three
 * callers may quietly ship fewer of them than the others.
 */

import { useTranslation } from 'react-i18next';
import { Alert, Pressable, Share, StyleSheet, View as RNView, type ViewStyle } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import { useMemo } from 'react';

import { Text, usePalette, type Palette } from '@/components/Themed';

export interface RecoveryPhraseCardProps {
    /** The phrase, space separated. Rendered as numbered words. */
    phrase: string;
    /**
     * The holder says they have saved it. Every caller does something
     * different afterwards, so the card only reports the press and never
     * assumes what it means.
     */
    onSaved: () => void;
    /** Optional override for the card container. */
    style?: ViewStyle;
}

export function RecoveryPhraseCard({ phrase, onSaved, style }: RecoveryPhraseCardProps) {
    const p = usePalette();
    const { t } = useTranslation();
    const styles = useMemo(() => makeStyles(p), [p]);

    const words = useMemo(() => phrase.trim().split(/\s+/).filter(Boolean), [phrase]);

    const copy = async () => {
        await Clipboard.setStringAsync(phrase);
        Alert.alert(t('common.copied'), t('secureWallet.copiedWarning'));
    };

    return (
        <RNView style={[styles.card, style]}>
            <Text style={styles.fieldLabel}>{t('secureWallet.saveWords')}</Text>

            <RNView style={styles.codesGrid}>
                {words.map((word, i) => (
                    <RNView key={`${i}-${word}`} style={styles.codeItem}>
                        <Text style={styles.codeText}>{i + 1}. {word}</Text>
                    </RNView>
                ))}
            </RNView>

            {/* Copy and export, so the phrase can be printed. The share sheet
                and the clipboard are both less private than paper (clipboard
                managers, cloud share targets), which is why the caution below
                stays next to the actions rather than being tucked away. */}
            <RNView style={styles.actions}>
                <Pressable style={styles.secondaryButton} onPress={copy}>
                    <Text style={styles.secondaryButtonText}>{t('common.copy')}</Text>
                </Pressable>
                <Pressable
                    style={styles.secondaryButton}
                    onPress={() => {
                        void Share.share({ message: phrase });
                    }}
                >
                    <Text style={styles.secondaryButtonText}>{t('secureWallet.sharePrint')}</Text>
                </Pressable>
            </RNView>

            <Text style={styles.helperText}>{t('secureWallet.paperAdvice')}</Text>

            <Pressable style={styles.primaryButton} onPress={onSaved}>
                <Text style={styles.primaryButtonText}>{t('secureWallet.savedIt')}</Text>
            </Pressable>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    card: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 16,
    },
    fieldLabel: {
        fontSize: 13,
        fontWeight: '600',
        color: p.textPrimary,
        marginBottom: 8,
    },
    codesGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        gap: 6,
        marginBottom: 12,
    },
    codeItem: {
        backgroundColor: p.cardAlt,
        borderRadius: 6,
        paddingVertical: 6,
        paddingHorizontal: 10,
    },
    codeText: {
        fontSize: 13,
        fontFamily: 'Inter',
        color: p.textPrimary,
        fontWeight: '500',
        letterSpacing: 0.5,
    },
    actions: { flexDirection: 'row', gap: 10 },
    secondaryButton: {
        flex: 1,
        backgroundColor: p.cardAlt,
        borderRadius: 10,
        paddingVertical: 10,
        alignItems: 'center',
        justifyContent: 'center',
    },
    secondaryButtonText: {
        fontSize: 14,
        fontWeight: '600',
        color: p.textPrimary,
    },
    helperText: {
        fontSize: 13,
        color: p.textMuted,
        lineHeight: 18,
        marginVertical: 12,
    },
    primaryButton: {
        backgroundColor: p.blue,
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
        justifyContent: 'center',
    },
    primaryButtonText: {
        fontSize: 16,
        fontWeight: '600',
        color: '#FFFFFF',
    },
});

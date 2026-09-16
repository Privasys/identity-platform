// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The form a resource service declares and the wallet draws.
 *
 * One control per field kind and nothing else. The component knows nothing
 * about mailboxes, passwords or providers: it is handed fields that
 * `services/capability-setup` has already refused or approved, and draws them.
 *
 * A masked field is masked everywhere it could leak. No autofill, so the value
 * is never offered to another app; no autocorrect, so it never reaches a
 * learned-words dictionary; and no context menu, so it cannot be copied on to
 * the system clipboard, which on a signed-in device is a second machine as
 * well. That closes paste too, which is the price of the guarantee.
 */

import { useState } from 'react';
import {
    Platform,
    Pressable,
    StyleSheet,
    Switch,
    TextInput,
    View as RNView,
} from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import type { SetupAnswers, SetupField } from '@/services/capability-setup';

interface Props {
    fields: SetupField[];
    answers: SetupAnswers;
    onChange: (name: string, value: string | boolean) => void;
    /** Field names that are required and still empty, marked after a submit. */
    missing?: string[];
    disabled?: boolean;
}

export function SetupForm({ fields, answers, onChange, missing = [], disabled }: Props) {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = makeStyles(p);

    return (
        <RNView style={styles.form}>
            {fields.map((f) => (
                <Field
                    key={f.name}
                    field={f}
                    value={answers[f.name]}
                    onChange={(v) => onChange(f.name, v)}
                    flagged={missing.includes(f.name)}
                    disabled={disabled}
                    styles={styles}
                    p={p}
                    t={t}
                />
            ))}
        </RNView>
    );
}

interface FieldProps {
    field: SetupField;
    value: string | boolean | undefined;
    onChange: (v: string | boolean) => void;
    flagged: boolean;
    disabled?: boolean;
    styles: ReturnType<typeof makeStyles>;
    p: Palette;
    t: (key: string) => string;
}

function Field({ field, value, onChange, flagged, disabled, styles, p, t }: FieldProps) {
    // Only ever affects whether the dots are drawn as characters. The value
    // itself is the same string the service will be sent either way.
    const [revealed, setRevealed] = useState(false);

    if (field.kind === 'switch') {
        return (
            <RNView style={styles.switchRow}>
                <RNView style={styles.switchText}>
                    <Text style={styles.label}>{field.title}</Text>
                    {!!field.description && <Text style={styles.hint}>{field.description}</Text>}
                </RNView>
                <Switch
                    value={value === true}
                    onValueChange={onChange}
                    disabled={disabled}
                    trackColor={{ false: p.border, true: p.green }}
                />
            </RNView>
        );
    }

    return (
        <RNView style={styles.field}>
            <RNView style={styles.labelRow}>
                <Text style={styles.label}>{field.title}</Text>
                {!field.required && <Text style={styles.optional}>{t('capability.setup.optional')}</Text>}
            </RNView>

            {field.kind === 'choice' ? (
                <RNView style={styles.choices}>
                    {(field.options ?? []).map((option) => {
                        const on = value === option;
                        return (
                            <Pressable
                                key={option}
                                style={[styles.choice, on && styles.choiceOn]}
                                onPress={() => onChange(option)}
                                disabled={disabled}
                            >
                                <Text style={[styles.choiceText, on && styles.choiceTextOn]}>
                                    {option}
                                </Text>
                            </Pressable>
                        );
                    })}
                </RNView>
            ) : (
                <RNView style={styles.inputRow}>
                    <TextInput
                        style={[
                            styles.input,
                            field.kind === 'secret' && styles.inputWithButton,
                            flagged && styles.inputFlagged,
                        ]}
                        value={typeof value === 'string' ? value : ''}
                        onChangeText={onChange}
                        editable={!disabled}
                        placeholderTextColor={p.textMuted}
                        autoCapitalize="none"
                        autoCorrect={false}
                        spellCheck={false}
                        keyboardType={field.kind === 'email' ? 'email-address' : 'default'}
                        secureTextEntry={field.kind === 'secret' && !revealed}
                        // A secret must not reach the keyboard's autofill, the
                        // password manager's save prompt, or the clipboard.
                        // `oneTimeCode` is the one iOS content type that asks
                        // for none of those on a secure field.
                        autoComplete={field.kind === 'secret' ? 'off' : field.kind === 'email' ? 'email' : 'off'}
                        textContentType={field.kind === 'secret' ? 'oneTimeCode' : field.kind === 'email' ? 'emailAddress' : 'none'}
                        importantForAutofill={field.kind === 'secret' ? 'no' : 'auto'}
                        contextMenuHidden={field.kind === 'secret'}
                        selectTextOnFocus={false}
                    />
                    {field.kind === 'secret' && (
                        // Typing a sixteen-character app password blind is how
                        // a holder gets it wrong twice. Revealing is their
                        // choice, on their own screen, and nothing leaves it.
                        <Pressable
                            style={styles.reveal}
                            onPress={() => setRevealed((r) => !r)}
                            disabled={disabled}
                            accessibilityRole="button"
                            accessibilityLabel={t(
                                revealed ? 'capability.setup.hide' : 'capability.setup.show',
                            )}
                        >
                            <Text style={styles.revealText}>
                                {t(revealed ? 'capability.setup.hide' : 'capability.setup.show')}
                            </Text>
                        </Pressable>
                    )}
                </RNView>
            )}

            {!!field.description && <Text style={styles.hint}>{field.description}</Text>}
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    form: { gap: 16, marginBottom: 8 },
    field: { gap: 6 },
    labelRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
    label: { fontSize: 14, fontWeight: '600', color: p.textPrimary },
    optional: { fontSize: 12, color: p.textMuted },
    hint: { fontSize: 12, color: p.textSecondary, lineHeight: 18 },
    inputRow: { justifyContent: 'center' },
    input: {
        backgroundColor: p.cardAlt,
        borderWidth: 1,
        borderColor: p.border,
        borderRadius: 10,
        paddingHorizontal: 14,
        paddingVertical: Platform.OS === 'ios' ? 13 : 9,
        fontSize: 16,
        color: p.textPrimary,
    },
    inputWithButton: { paddingRight: 68 },
    inputFlagged: { borderColor: p.dangerBorder },
    reveal: { position: 'absolute', right: 6, paddingHorizontal: 8, paddingVertical: 8 },
    revealText: { fontSize: 13, fontWeight: '600', color: p.blue },
    switchRow: { flexDirection: 'row', alignItems: 'center', gap: 12 },
    switchText: { flex: 1, gap: 4 },
    choices: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
    choice: {
        backgroundColor: p.cardAlt,
        borderWidth: 1,
        borderColor: p.border,
        borderRadius: 999,
        paddingHorizontal: 14,
        paddingVertical: 8,
    },
    choiceOn: { backgroundColor: p.blue, borderColor: p.blue },
    choiceText: { fontSize: 14, color: p.textPrimary },
    choiceTextOn: { color: '#FFFFFF', fontWeight: '600' },
});

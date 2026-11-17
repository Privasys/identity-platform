// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One Drive file, shown in the wallet's own screen. The plaintext comes from
 * the Drive enclave over the attested channel (services/drive-files); a copy
 * lives in the wallet's cache while this screen is open and is deleted when
 * it closes.
 *
 * Images and text are drawn here. A PDF or another document opens in Apple's
 * Quick Look on iOS, over this screen; on Android a PDF's pages are drawn by
 * the system's renderer and shown here. Anything else can be saved or shared
 * through the OS sheet, which takes a copy out of Drive's protection, and the
 * screen says so.
 */

import { Ionicons } from '@expo/vector-icons';
import { File } from 'expo-file-system';
import { Image } from 'expo-image';
import { useLocalSearchParams } from 'expo-router';
import * as Sharing from 'expo-sharing';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ActivityIndicator, Platform, Pressable, ScrollView, StyleSheet, useWindowDimensions, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { copyForViewing, discardCopy, fileKind, formatSize, type FileKind } from '@/services/drive-files';
import * as FilePreview from '../../modules/file-preview/src/index';

/** Beyond this a file is not pulled onto the phone: it travels in memory. */
const MAX_BYTES = 25 * 1024 * 1024;
/** Text beyond this is cut, with a note. */
const MAX_TEXT = 200 * 1024;
const MAX_PDF_PAGES = 100;

type View =
    | { kind: 'loading' }
    | { kind: 'image'; uri: string }
    | { kind: 'text'; text: string; cut: boolean }
    | { kind: 'pdf-pages'; pages: FilePreview.RenderedPage[]; pageCount: number }
    | { kind: 'quicklook' }
    | { kind: 'other' }
    | { kind: 'too-large' }
    | { kind: 'failed'; message: string };

export default function DriveFileScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const { width } = useWindowDimensions();
    const params = useLocalSearchParams<{ tenant?: string; id?: string; name?: string; mime?: string; size?: string }>();
    const name = params.name || t('drive.file');
    const size = Number(params.size) || 0;
    const [view, setView] = useState<View>({ kind: 'loading' });
    const copy = useRef<File | null>(null);

    const quickLook = useCallback(async () => {
        if (!copy.current) return;
        try {
            await FilePreview.preview(copy.current.uri.replace(/^file:\/\//, ''), name);
        } catch (e) {
            setView({ kind: 'failed', message: e instanceof Error ? e.message : String(e) });
        }
    }, [name]);

    useEffect(() => {
        let live = true;
        void (async () => {
            if (!params.tenant || !params.id) {
                setView({ kind: 'failed', message: t('drive.fileFailed') });
                return;
            }
            if (size > MAX_BYTES) {
                setView({ kind: 'too-large' });
                return;
            }
            const item = { tenantId: params.tenant, id: params.id, kind: 'file' as const, name, sizeBytes: size, mime: params.mime || undefined };
            const kind: FileKind = fileKind(item);
            try {
                const f = await copyForViewing(item);
                if (!live) {
                    discardCopy(f);
                    return;
                }
                copy.current = f;
                const path = f.uri.replace(/^file:\/\//, '');
                if (kind === 'image') {
                    setView({ kind: 'image', uri: f.uri });
                } else if (kind === 'text') {
                    const text = await f.text();
                    setView({ kind: 'text', text: text.slice(0, MAX_TEXT), cut: text.length > MAX_TEXT });
                } else if (Platform.OS === 'ios' && (await FilePreview.canPreview(path))) {
                    setView({ kind: 'quicklook' });
                    await FilePreview.preview(path, name);
                } else if (Platform.OS === 'android' && kind === 'pdf') {
                    const r = await FilePreview.renderPdf(path, Math.min(width * 2, 1600), MAX_PDF_PAGES);
                    if (live) setView({ kind: 'pdf-pages', pages: r.pages, pageCount: r.pageCount });
                } else {
                    setView({ kind: 'other' });
                }
            } catch (e) {
                if (live) setView({ kind: 'failed', message: e instanceof Error ? e.message : t('drive.fileFailed') });
            }
        })();
        return () => {
            live = false;
            if (copy.current) discardCopy(copy.current);
            copy.current = null;
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [params.tenant, params.id]);

    const share = useCallback(async () => {
        if (!copy.current) return;
        try {
            await Sharing.shareAsync(copy.current.uri, { dialogTitle: name, mimeType: params.mime || undefined });
        } catch {
            // The holder closed the sheet.
        }
    }, [name, params.mime]);

    const canShare = view.kind !== 'loading' && view.kind !== 'too-large' && view.kind !== 'failed';

    const body = (() => {
        switch (view.kind) {
            case 'loading':
                return (
                    <RNView style={styles.centre}>
                        <ActivityIndicator size="large" color={p.blue} />
                        <Text style={styles.note}>{t('drive.fileOpening')}</Text>
                    </RNView>
                );
            case 'image':
                return <Image source={{ uri: view.uri }} style={[styles.image, { width: width - 40, height: width - 40 }]} contentFit="contain" />;
            case 'text':
                return (
                    <>
                        <Text style={styles.text} selectable>
                            {view.text}
                        </Text>
                        {view.cut ? <Text style={styles.note}>{t('drive.textCut')}</Text> : null}
                    </>
                );
            case 'pdf-pages':
                return (
                    <>
                        {view.pages.map((pg) => (
                            <Image
                                key={pg.uri}
                                source={{ uri: pg.uri }}
                                style={[styles.page, { width: width - 40, height: ((width - 40) * pg.height) / pg.width }]}
                                contentFit="contain"
                            />
                        ))}
                        {view.pageCount > view.pages.length ? (
                            <Text style={styles.note}>
                                {t('drive.pdfMorePages', { shown: view.pages.length, total: view.pageCount })}
                            </Text>
                        ) : null}
                    </>
                );
            case 'quicklook':
                return (
                    <RNView style={styles.centre}>
                        <Ionicons name="document-text-outline" size={44} color={p.textMuted} />
                        <Pressable style={styles.primary} onPress={() => void quickLook()} accessibilityRole="button">
                            <Text style={styles.primaryText}>{t('drive.fileOpenAgain')}</Text>
                        </Pressable>
                    </RNView>
                );
            case 'other':
                return (
                    <RNView style={styles.centre}>
                        <Ionicons name="document-outline" size={44} color={p.textMuted} />
                        <Text style={styles.message}>{t('drive.fileCannotShow')}</Text>
                    </RNView>
                );
            case 'too-large':
                return (
                    <RNView style={styles.centre}>
                        <Ionicons name="cloud-outline" size={44} color={p.textMuted} />
                        <Text style={styles.message}>{t('drive.fileTooLarge', { size: formatSize(size, t) })}</Text>
                    </RNView>
                );
            case 'failed':
                return (
                    <RNView style={styles.centre}>
                        <Ionicons name="alert-circle-outline" size={44} color={p.danger} />
                        <Text style={styles.message}>{t('drive.fileFailed')}</Text>
                        <Text style={styles.note}>{view.message}</Text>
                    </RNView>
                );
        }
    })();

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={name} />
            <ScrollView contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}>
                {body}
                {canShare ? (
                    <RNView style={styles.exportBox}>
                        <Pressable style={styles.secondary} onPress={() => void share()} accessibilityRole="button">
                            <Ionicons name="share-outline" size={18} color={p.textPrimary} />
                            <Text style={styles.secondaryText}>{t('drive.fileExport')}</Text>
                        </Pressable>
                        <Text style={styles.note}>{t('drive.fileExportNote')}</Text>
                    </RNView>
                ) : null}
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        screen: { flex: 1, backgroundColor: p.screenBg },
        body: { padding: 20, gap: 14 },
        centre: { alignItems: 'center', gap: 12, marginTop: 40 },
        image: { alignSelf: 'center', borderRadius: 12, backgroundColor: p.card },
        page: { alignSelf: 'center', backgroundColor: '#FFFFFF', borderRadius: 4 },
        text: {
            fontSize: 13,
            lineHeight: 19,
            color: p.textPrimary,
            fontFamily: Platform.select({ ios: 'Menlo', android: 'monospace' }),
            backgroundColor: p.card,
            padding: 14,
            borderRadius: 12,
        },
        message: { fontSize: 15, lineHeight: 22, color: p.textSecondary, textAlign: 'center' },
        note: { fontSize: 12.5, lineHeight: 18, color: p.textMuted, textAlign: 'center' },
        primary: { backgroundColor: p.action, borderRadius: 14, paddingVertical: 14, paddingHorizontal: 24, alignItems: 'center' },
        primaryText: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
        exportBox: { gap: 8, marginTop: 8 },
        secondary: {
            flexDirection: 'row',
            gap: 8,
            justifyContent: 'center',
            alignItems: 'center',
            backgroundColor: p.card,
            borderWidth: 1,
            borderColor: p.border,
            borderRadius: 12,
            paddingVertical: 13,
        },
        secondaryText: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    });

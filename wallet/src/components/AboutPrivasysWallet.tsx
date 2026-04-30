import { StyleSheet } from 'react-native';

import Colors from '@/constants/colors';

import { ExternalLink } from './ExternalLink';
import { Text, View } from './Themed';

export default function AboutPrivasysWallet() {
    return (
        <View>
            <View style={styles.getStartedContainer}>
                <Text
                    style={styles.getStartedText}
                    lightColor="rgba(0,0,0,0.8)"
                    darkColor="rgba(255,255,255,0.8)"
                >
                    This application is developed by Privasys&nbsp;Ltd. Registered in England and
                    Wales, company number 16866500.
                </Text>
            </View>

            <View style={styles.helpContainer}>
                <ExternalLink style={styles.helpLink} href="https://privasys.org">
                    <Text style={styles.helpLinkText} lightColor={Colors.light.tint}>
                        Visit https://privasys.org
                    </Text>
                </ExternalLink>
            </View>
        </View>
    );
}

const styles = StyleSheet.create({
    getStartedContainer: { marginHorizontal: 10 },
    homeScreenFilename: { marginVertical: 7 },
    codeHighlightContainer: { borderRadius: 3, paddingHorizontal: 4 },
    getStartedText: { fontSize: 17, lineHeight: 24 },
    helpContainer: { marginTop: 15, marginHorizontal: 20, alignItems: 'center' },
    helpLink: { paddingVertical: 0 },
    helpLinkText: { textAlign: 'center' }
});

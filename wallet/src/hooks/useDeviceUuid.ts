import * as Crypto from 'expo-crypto';
import * as SecureStore from '@/utils/storage';
import { useEffect, useState } from 'react';

const UUID_KEY = 'v0-secure-device-uuid';
let ambientDeviceId: string | null = null;

export function useDeviceUuid() {
    const [uuid, setUuid] = useState<string | null>(ambientDeviceId);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        const fetchOrGenerateUuid = async () => {
            try {
                // 1. Try to fetch the UUID from SecureStore
                const storedUuid = await SecureStore.getItemAsync(UUID_KEY);

                if (storedUuid) {
                    // If found, use it
                    ambientDeviceId = storedUuid;
                    setUuid(storedUuid);
                } else {
                    // 2. If not found, generate a new UUID
                    const newUuid = Crypto.randomUUID();

                    // 3. Save the new UUID securely
                    await SecureStore.setItemAsync(UUID_KEY, newUuid);
                    ambientDeviceId = newUuid;
                    setUuid(newUuid);
                }
            } catch (error) {
                console.error('Error fetching or generating UUID:', error);
                // Handle errors appropriately in a real app
            } finally {
                setIsLoading(false);
            }
        };

        fetchOrGenerateUuid();
    }, []); // The empty dependency array ensures this runs only once on mount

    return { uuid, isLoading };
}

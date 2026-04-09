'use client';
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Base64 } from 'js-base64';
import { useCallback, useState } from 'react';

export function useWebAuthnAssertion(
    begin: { mutateAsync: (args: object) => Promise<any> },
    finish: { mutateAsync: (args: { body: any }) => Promise<any> }
) {
    const [isPending, setIsPending] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const loginAsync = useCallback(async () => {
        try {
            setIsPending(true);
            const credentialRequestOptions = await begin.mutateAsync({});

            credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(
                credentialRequestOptions.publicKey.challenge
            ) as any;
            credentialRequestOptions.publicKey.allowCredentials?.forEach(function (listItem: any) {
                listItem.id = Base64.toUint8Array(listItem.id) as any;
            });

            const assertion = await navigator.credentials.get({
                publicKey: credentialRequestOptions.publicKey,
            });

            if (!assertion) {
                return false;
            }

            await finish.mutateAsync({
                body: {
                    id: assertion.id,
                    // @ts-expect-error Someone fucked up Credential type definitions
                    rawId: Base64.fromUint8Array(new Uint8Array(assertion.rawId), true),
                    type: assertion.type,
                    response: {
                        authenticatorData: Base64.fromUint8Array(
                            // @ts-expect-error Someone fucked up Credential type definitions
                            new Uint8Array(assertion.response.authenticatorData),
                            true
                        ),
                        clientDataJSON: Base64.fromUint8Array(
                            // @ts-expect-error Someone fucked up Credential type definitions
                            new Uint8Array(assertion.response.clientDataJSON),
                            true
                        ),
                        signature: Base64.fromUint8Array(
                            // @ts-expect-error Someone fucked up Credential type definitions
                            new Uint8Array(assertion.response.signature),
                            true
                        ),
                        userHandle: Base64.fromUint8Array(
                            // @ts-expect-error Someone fucked up Credential type definitions
                            new Uint8Array(assertion.response.userHandle),
                            true
                        ),
                    },
                },
            });
            setError(null);
            return true;
        } catch (error) {
            setError(error as any);
            return false;
        } finally {
            setIsPending(false);
        }
    }, [begin, finish]);

    return { loginAsync, isPending, error };
}

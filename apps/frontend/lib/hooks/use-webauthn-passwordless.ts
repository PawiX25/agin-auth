'use client';
import { $api } from '@lib/providers/api';
import { useLoginSuccess } from './use-login-success';
import { useWebAuthnAssertion } from './use-webauthn-core';

export function useWebAuthnPasswordless() {
    // Discoverable WebAuthn can authenticate a different account than the identifier currently
    // typed into the login form, so we must not persist a first-factor preference from it.
    const { onSuccess } = useLoginSuccess({
        firstFactor: 'webauthnpasswordless',
    });
    const begin = $api.useMutation('post', '/api/login/webauthn/passwordless/start');
    const finish = $api.useMutation('post', '/api/login/webauthn/passwordless/finish', { onSuccess });
    return useWebAuthnAssertion(begin, finish);
}

import { LoginIcon } from '@components/ui/login-icon';
import { IconAlertCircle, IconFingerprint } from '@tabler/icons-react';
import { screenAtom } from './page';
import { LinkComponent } from '@components/ui/link';
import { useSetAtom } from 'jotai';
import { useCallback } from 'react';
import { useWebAuthn2FA } from '@lib/hooks';
import { Button } from '@components/ui/button';
import { useHotkeys } from '@mantine/hooks';
import { Alert, AlertDescription, AlertTitle } from '@components/ui/alert';

export function WebAuthn() {
    const setScreen = useSetAtom(screenAtom);

    const { loginAsync, isPending, error } = useWebAuthn2FA();

    const startAuth = useCallback(async () => {
        await loginAsync();
    }, [loginAsync]);

    useHotkeys([['Enter', startAuth]]);

    return (
        <div className="flex flex-col items-center">
            <LoginIcon>
                <IconFingerprint />
            </LoginIcon>
            <div className="mt-4 flex flex-col gap-1">
                <h1 className="font-semibold text-xl text-center">Use a security key</h1>
                <p className="text-sm text-center text-muted-foreground">
                    Insert your security key into your device or use a passkey.
                </p>
            </div>
            <div className="w-sm mt-6 flex flex-col gap-4">
                {error && (
                    <Alert variant="destructive">
                        <IconAlertCircle />
                        <AlertTitle>Authentication Failed</AlertTitle>
                        <AlertDescription>
                            An error occurred during authentication.
                        </AlertDescription>
                    </Alert>
                )}
                <Button onClick={startAuth} disabled={isPending}>
                    <IconFingerprint /> Read security key
                </Button>
                {/* <div className="flex justify-center mb-1">Loading</div> */}
                <div className="text-muted-foreground text-center text-sm">
                    <LinkComponent>
                        <div onClick={() => setScreen('two-factor-options')}>More Options</div>
                    </LinkComponent>
                </div>
            </div>
        </div>
    );
}

'use client';

import { Form } from '@components/ui/form';
import { useForm } from 'react-hook-form';
import { LinkComponent } from '@components/ui/link';
import z from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { atom, useAtomValue, useSetAtom } from 'jotai';
import { useEffect } from 'react';
import { Welcome } from './welcome';
import { LoginOptions } from './login-options';
import { Password } from './password';
import { TwoFactorOptions } from './two-factor-options';
import { Totp } from './totp';
import { AnimatePresence, motion } from 'motion/react';
import { RecoveryCode } from './recovery-code';
import { WebAuthn } from './webauthn';
import { WebAuthnPasswordless } from './webauthn-passwordless';
import { Pgp } from './pgp';

export const formSchema = z.object({
    username: z.string().min(1, 'Username is required'),
    password: z.string().optional(),
    totp: z.string().optional(),
    recovery_code: z.string().optional(),
    pgp_signature: z.string().optional(),
});

export type FormSchema = z.infer<typeof formSchema>;

export type LoginScreen =
    | 'welcome'
    | 'webauthn'
    | 'webauthnpasswordless'
    | 'password'
    | 'totp'
    | 'pgp'
    | 'login-options'
    | 'recoverycode'
    | 'two-factor-options';

export const screenAtom = atom<LoginScreen>('welcome');

const screensRequiringUsername: LoginScreen[] = [
    'password',
    'pgp',
    'login-options',
    'two-factor-options',
    'totp',
    'recoverycode',
    'webauthn',
];

export default function Page() {
    const screen = useAtomValue(screenAtom);
    const setScreen = useSetAtom(screenAtom);

    const form = useForm<FormSchema>({
        resolver: zodResolver(formSchema),
        defaultValues: {
            username: '',
            password: '',
            totp: '',
            recovery_code: '',
            pgp_signature: '',
        },
    });

    const username = form.watch('username');

    useEffect(() => {
        if (screensRequiringUsername.includes(screen) && !username?.trim()) {
            setScreen('welcome');
        }
    }, [screen, username, setScreen]);

    return (
        <Form {...form}>
            <AnimatePresence mode="wait" initial={false}>
                <motion.div
                    key={screen}
                    transition={{ duration: 0.2 }}
                    initial={{ opacity: 0, x: 8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -8 }}
                >
                    {screen === 'welcome' && <Welcome />}
                    {screen === 'login-options' && <LoginOptions />}
                    {screen === 'password' && <Password />}
                    {screen === 'two-factor-options' && <TwoFactorOptions />}
                    {screen === 'totp' && <Totp />}
                    {screen === 'recoverycode' && <RecoveryCode />}
                    {screen === 'webauthn' && <WebAuthn />}
                    {screen === 'webauthnpasswordless' && <WebAuthnPasswordless />}
                    {screen === 'pgp' && <Pgp />}
                </motion.div>
            </AnimatePresence>
            <div className="text-muted-foreground text-xs absolute left-4 right-4 bottom-4 text-center">
                By signing in you accept our{' '}
                <LinkComponent>
                    <a>Privacy Policy</a>
                </LinkComponent>
            </div>
        </Form>
    );
}

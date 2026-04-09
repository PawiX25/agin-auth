import { LoginIcon } from '@components/ui/login-icon';
import { IconArrowRight, IconFingerprint, IconKey, IconPassword, IconShieldLock } from '@tabler/icons-react';
import { FormSchema, screenAtom } from './page';
import { useSetAtom } from 'jotai';
import { LoginOption, LoginOptionProps } from '@components/ui/login-option';
import Link from 'next/link';
import { LinkComponent } from '@components/ui/link';
import { useFormContext } from 'react-hook-form';
import { FIRST_FACTOR_OPTIONS, getPreferredFirstFactor } from './first-factor';

export const OPTIONS_MAP: Record<(typeof FIRST_FACTOR_OPTIONS)[number], LoginOptionProps> = {
    password: {
        title: 'Password',
        icon: IconPassword,
        rightSection: <IconArrowRight className="size-4 text-muted-foreground" />,
    },
    webauthnpasswordless: {
        title: 'Security key / Passkey',
        icon: IconFingerprint,
        rightSection: <IconArrowRight className="size-4 text-muted-foreground" />,
    },
    pgp: {
        title: 'PGP Key',
        icon: IconKey,
        rightSection: <IconArrowRight className="size-4 text-muted-foreground" />,
    },
};

export function LoginOptions() {
    const setScreen = useSetAtom(screenAtom);
    const form = useFormContext<FormSchema>();
    const username = form.watch('username');
    const preferred = getPreferredFirstFactor(username);
    const orderedOptions = preferred
        ? [preferred, ...FIRST_FACTOR_OPTIONS.filter((o) => o !== preferred)]
        : FIRST_FACTOR_OPTIONS;

    return (
        <div className="flex flex-col items-center">
            <LoginIcon>
                <IconShieldLock />
            </LoginIcon>
            <div className="mt-4 flex flex-col gap-1">
                <h1 className="font-semibold text-xl text-center">Choose how to continue</h1>
                <p className="text-sm text-center text-muted-foreground">
                    Continue as {username}{' '}
                    <LinkComponent onClick={() => setScreen('welcome')}>Not you?</LinkComponent>
                </p>
            </div>
            <div className="w-sm mt-6 flex flex-col gap-3">
                {orderedOptions.map((option) => (
                    <LoginOption
                        {...OPTIONS_MAP[option]}
                        clickable
                        key={option}
                        className="m-0"
                        onClick={() => setScreen(option)}
                    />
                ))}
                <div className="text-muted-foreground text-center text-sm">
                    <LinkComponent>
                        <Link
                            href={`/forgot-password${username ? `?email=${encodeURIComponent(username)}` : ''}`}
                        >
                            Forgot Password?
                        </Link>
                    </LinkComponent>
                </div>
            </div>
        </div>
    );
}

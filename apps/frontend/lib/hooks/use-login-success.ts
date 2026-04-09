import { rememberPreferredFirstFactor } from '@/app/(loginform)/login/first-factor';
import { screenAtom } from '@/app/(loginform)/login/page';
import { twofactorOptionsAtom } from '@/app/(loginform)/login/two-factor-options';
import { paths } from 'api-schema';
import { useSetAtom } from 'jotai';
import { useRouter, useSearchParams } from 'next/navigation';
import { useCallback } from 'react';

export type LoginSuccessResponse =
    paths['/api/login/password']['post']['responses']['200']['content']['application/json'];

type UseLoginSuccessOptions = {
    firstFactor?: 'password' | 'webauthnpasswordless' | 'pgp';
    username?: string;
};

export function useLoginSuccess(options: UseLoginSuccessOptions = {}) {
    const router = useRouter();
    const params = useSearchParams();
    const next = params.get('next') || '/';

    const setScreen = useSetAtom(screenAtom);
    const setOptions = useSetAtom(twofactorOptionsAtom);

    const onSuccess = useCallback(
        ({ two_factor_required, recent_factor, second_factors }: LoginSuccessResponse) => {
            if (options.firstFactor && options.username) {
                rememberPreferredFirstFactor(options.username, options.firstFactor);
            }

            if (!two_factor_required || !second_factors) {
                if (typeof next === 'string' && next.startsWith('/')) {
                    router.replace(next);
                } else {
                    router.replace('/');
                }
                return;
            }

            setOptions(second_factors);

            if (second_factors.length === 1) return setScreen(second_factors[0]);
            if (recent_factor) return setScreen(recent_factor);
            setScreen('two-factor-options');
        },
        [next, options.firstFactor, options.username, router, setOptions, setScreen]
    );

    return { onSuccess };
}

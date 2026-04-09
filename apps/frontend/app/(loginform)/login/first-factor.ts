export type FirstFactorOption = 'password' | 'webauthnpasswordless' | 'pgp';

export const FIRST_FACTOR_OPTIONS: FirstFactorOption[] = [
    'password',
    'webauthnpasswordless',
    'pgp',
];

const STORAGE_PREFIX = 'agin-auth:last-first-factor:';

function normalizeIdentifier(identifier: string) {
    return identifier.trim().toLowerCase();
}

function isFirstFactorOption(value: string): value is FirstFactorOption {
    return FIRST_FACTOR_OPTIONS.includes(value as FirstFactorOption);
}

export function getPreferredFirstFactor(identifier: string): FirstFactorOption | null {
    if (typeof window === 'undefined') {
        return null;
    }

    const normalized = normalizeIdentifier(identifier);
    if (!normalized) {
        return null;
    }

    try {
        const value = window.localStorage.getItem(`${STORAGE_PREFIX}${normalized}`);
        if (!value || !isFirstFactorOption(value)) {
            return null;
        }
        return value;
    } catch {
        return null;
    }
}

export function rememberPreferredFirstFactor(
    identifier: string,
    factor: FirstFactorOption
) {
    if (typeof window === 'undefined') {
        return;
    }

    const normalized = normalizeIdentifier(identifier);
    if (!normalized) {
        return;
    }

    try {
        window.localStorage.setItem(`${STORAGE_PREFIX}${normalized}`, factor);
    } catch {
        // Silently fail — preference is optional
    }
}

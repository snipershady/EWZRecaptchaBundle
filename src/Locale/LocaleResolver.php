<?php

namespace EWZ\Bundle\RecaptchaBundle\Locale;

use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Depending on the configuration resolves the correct locale for the reCAPTCHA.
 */
final readonly class LocaleResolver
{
    /**
     * @param string       $defaultLocale
     * @param bool         $useLocaleFromRequest
     * @param RequestStack $requestStack
     */
    public function __construct(private string $defaultLocale, private bool $useLocaleFromRequest, private RequestStack $requestStack)
    {
    }

    /**
     * @return string The resolved locale key, depending on configuration
     */
    public function resolve(): string
    {
        return $this->useLocaleFromRequest
            ? $this->requestStack->getCurrentRequest()->getLocale()
            : $this->defaultLocale;
    }
}

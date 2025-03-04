<?php

namespace EWZ\Bundle\RecaptchaBundle\Form\Type;

use EWZ\Bundle\RecaptchaBundle\Locale\LocaleResolver;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * A field for entering a recaptcha text.
 */
class EWZRecaptchaType extends AbstractEWZRecaptchaType
{
    /**
     * @param string         $publicKey      Recaptcha public key
     * @param bool           $enabled        Recaptcha status
     * @param bool           $ajax           Ajax status
     * @param LocaleResolver $localeResolver
     */
    public function __construct(string $publicKey, bool $enabled, /**
     * Use AJAX api?
     */
    protected bool $ajax, protected LocaleResolver $localeResolver, string $apiHost = 'www.google.com')
    {
        parent::__construct($publicKey, $enabled, $apiHost);
    }

    /**
     * {@inheritdoc}
     */
    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults(
            [
            'compound' => false,
            'language' => $this->localeResolver->resolve(),
            'public_key' => null,
            'url_challenge' => null,
            'url_noscript' => null,
            'attr' => [
                'options' => [
                    'theme' => 'light',
                    'type' => 'image',
                    'size' => 'normal',
                    'callback' => null,
                    'expiredCallback' => null,
                    'bind' => null,
                    'defer' => false,
                    'async' => false,
                    'badge' => null,
                ],
            ],
    ]);
    }

    /**
     * {@inheritdoc}
     */
    #[\Override]
    public function getParent(): string
    {
        return TextType::class;
    }

    /**
     * Gets the Javascript source URLs.
     *
     * @param string $key The script name
     *
     * @return string The javascript source URL
     */
    public function getScriptURL(string $key): ?string
    {
        return $this->scripts[$key] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    protected function addCustomVars(FormView $view, FormInterface $form, array $options): void
    {
        $view->vars = array_replace($view->vars, [
            'ewz_recaptcha_ajax' => $this->ajax,
        ]);

        if (!isset($options['language'])) {
            $options['language'] = $this->localeResolver->resolve();
        }

        if (!$this->ajax) {
            $view->vars = array_replace($view->vars, [
                'url_challenge' => sprintf('%s?hl=%s', $this->recaptchaApiServer, $options['language']),
            ]);
        } else {
            $view->vars = array_replace($view->vars, [
                'url_api' => sprintf('//%s/recaptcha/api/js/recaptcha_ajax.js', $this->apiHost),
            ]);
        }
    }
}

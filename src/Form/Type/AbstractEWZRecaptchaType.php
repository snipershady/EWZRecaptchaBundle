<?php

namespace EWZ\Bundle\RecaptchaBundle\Form\Type;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;

abstract class AbstractEWZRecaptchaType extends AbstractType
{
    /**
     * The reCAPTCHA server URL.
     *
     * @var string
     */
    protected string $recaptchaApiServer;

    /**
     * @param string $publicKey Recaptcha public key
     * @param bool $enabled   Recaptcha status
     * @param string $apiHost   Api host
     */
    public function __construct(/**
     * The public key.
     */
    protected string $publicKey, /**
     * Enable recaptcha?
     */
    protected bool $enabled, /**
     * The API server host name.
     */
    protected string $apiHost = 'www.google.com')
    {
        $this->recaptchaApiServer = sprintf('https://%s/recaptcha/api.js', $this->apiHost);
    }

    /**
     * {@inheritdoc}
     */
    public function buildView(FormView $view, FormInterface $form, array $options): void
    {
        $view->vars = array_replace($view->vars, [
            'ewz_recaptcha_enabled' => $this->enabled,
            'ewz_recaptcha_api_host' => $this->apiHost,
            'ewz_recaptcha_api_uri' => $this->recaptchaApiServer,
            'public_key' => $this->publicKey,
        ]);

        if (!$this->enabled) {
            return;
        }

        $this->addCustomVars($view, $form, $options);
    }

    /**
     * {@inheritdoc}
     */
    #[\Override]
    public function getBlockPrefix(): string
    {
        return 'ewz_recaptcha';
    }

    /**
     * Gets the public key.
     *
     * @return string The javascript source URL
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * Gets the API host name.
     *
     * @return string The hostname for API
     */
    public function getApiHost(): string
    {
        return $this->apiHost;
    }

    abstract protected function addCustomVars(FormView $view, FormInterface $form, array $options): void;
}

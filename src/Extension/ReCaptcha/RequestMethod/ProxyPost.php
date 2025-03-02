<?php

namespace EWZ\Bundle\RecaptchaBundle\Extension\ReCaptcha\RequestMethod;

use ReCaptcha\RequestMethod;
use ReCaptcha\RequestParameters;

/**
 * Sends POST requests to the reCAPTCHA service though a proxy.
 */
class ProxyPost implements RequestMethod
{
    /**
     * The reCAPTCHA verify server URL.
     *
     * @var string
     */
    private readonly string $recaptchaVerifyUrl;

    /** @var array */
    private array $cache;

    /**
     * Constructor.
     *
     * @param array    $httpProxy
     * @param string   $recaptchaVerifyServer
     * @param int|null $timeout
     */
    public function __construct(/**
     * HTTP Proxy informations.
     */
    private array $httpProxy, string $recaptchaVerifyServer, /**
     * The timeout for the reCAPTCHA verification.
     */
    private readonly ?int $timeout)
    {
        $this->recaptchaVerifyUrl = ($recaptchaVerifyServer ?: 'https://www.google.com').'/recaptcha/api/siteverify';
        $this->cache = [];
    }

    /**
     * Submit the POST request with the specified parameters.
     *
     * @param RequestParameters $params Request parameters
     *
     * @return string Body of the reCAPTCHA response
     */
    public function submit(RequestParameters $params): string
    {
        $cacheKey = $params->toQueryString();
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }

        $proxyAuth = !empty($this->httpProxy['auth'])
            ? sprintf('Proxy-Authorization: Basic %s', base64_encode((string) $this->httpProxy['auth']))
            : null;

        /**
         * PHP 5.6.0 changed the way you specify the peer name for SSL context options.
         * Using "CN_name" will still work, but it will raise deprecated errors.
         */
        $peerKey = version_compare(PHP_VERSION, '5.6.0', '<') ? 'CN_name' : 'peer_name';
        $options = [
            'http' => [
                'header' => sprintf("Content-type: application/x-www-form-urlencoded\r\n%s", $proxyAuth),
                'method' => 'POST',
                'content' => $params->toQueryString(),
                // Force the peer to validate (not needed in 5.6.0+, but still works)
                'verify_peer' => true,
                // Force the peer validation to use www.google.com
                $peerKey => 'www.google.com',

                'proxy' => sprintf('tcp://%s:%s', $this->httpProxy['host'], $this->httpProxy['port']),
                // While this is a non-standard request format, some proxy servers require it.
                'request_fulluri' => true,
                ],
            ];
        if (null !== $this->timeout) {
            $options['http']['timeout'] = $this->timeout;
        }
        $context = stream_context_create($options);

        $result = file_get_contents($this->recaptchaVerifyUrl, false, $context);

        $this->cache[$cacheKey] = $result;

        return $result;
    }
}

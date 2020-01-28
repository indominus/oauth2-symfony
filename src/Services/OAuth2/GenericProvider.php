<?php

namespace App\Services\OAuth2;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use League\OAuth2\Client\Provider\GenericProvider as BaseGenericProvider;

class GenericProvider extends BaseGenericProvider
{

    /**
     * GenericProvider constructor.
     *
     * @param UrlGeneratorInterface $urlGenerator
     */
    public function __construct(UrlGeneratorInterface $urlGenerator)
    {

        $options['clientId'] = $_ENV['CLIENT_ID'];
        $options['clientSecret'] = $_ENV['CLIENT_SECRET'];
        $options['redirectUri'] = $urlGenerator->generate('app.callback', [], UrlGeneratorInterface::ABSOLUTE_URL);
        $options['urlAuthorize'] = $_ENV['CLIENT_AUTHORIZE_ENDPOINT'];
        $options['urlAccessToken'] = $_ENV['CLIENT_ACCESS_TOKEN_ENDPOINT'];
        $options['urlResourceOwnerDetails'] = $_ENV['CLIENT_RESOURCE_OWNER_ENDPOINT'];

        parent::__construct($options, []);
    }

    /**
     * @return Client|ClientInterface
     */
    public function getHttpClient()
    {
        return new Client([
            'verify' => !$_ENV['APP_ENV'] === 'dev'
        ]);
    }
}
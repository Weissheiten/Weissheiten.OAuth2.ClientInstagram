<?php
namespace Weissheiten\OAuth2\ClientInstagram\Endpoint;

/*                                                                                      *
 * This script belongs to the TYPO3 Flow package "Weissheiten.OAuth2.ClientInstagram".  *
 *                                                                                      */

/**
 * @Flow\Scope("singleton")
 */

use Flowpack\OAuth2\Client\Exception as OAuth2Exception;
use Flowpack\Oauth2\Client\Endpoint\AbstractHttpTokenEndpoint;
use Flowpack\Oauth2\Client\Endpoint\TokenEndpointInterface;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Http\Request;
use TYPO3\Flow\Http\Uri;
use TYPO3\Flow\Log\SecurityLoggerInterface;

class InstagramTokenEndpoint extends AbstractHttpTokenEndpoint implements TokenEndpointInterface {
    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;
    /**
     * Inspect the received access token
     *
     * @param string $tokenToInspect
     * @return array
     * @throws OAuth2Exception
     */
    public function requestValidatedTokenInformation($tokenToInspect) {
        return [];
    }
    /**
     * @param $shortLivedToken
     * @return string
     */
    public function requestLongLivedToken($shortLivedToken) {
        return $this->requestAccessToken('instagram_exchange_token', array('instagram_exchange_token' => $shortLivedToken));
    }
}
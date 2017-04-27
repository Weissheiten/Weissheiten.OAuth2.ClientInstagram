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
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Uri;
use Neos\Flow\Log\SecurityLoggerInterface;
// uses because of having to override the requestAccessToken function
use Neos\Utility\Arrays;

class InstagramTokenEndpoint extends AbstractHttpTokenEndpoint implements TokenEndpointInterface {
    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;


    /**
     * @Flow\Inject
     * @var \Weissheiten\OAuth2\ClientInstagram\Utility\InstagramApiClient
     */
    protected $instagramApiClient;

    /**
     * Inspect the received access token
     *
     * @param string $tokenToInspect
     * @return array
     * @throws OAuth2Exception
     */
    public function validateSecureRequestCapability($accessToken) {
        $this->instagramApiClient->setCurrentAccessToken($accessToken);
        $responseData = $this->instagramApiClient->getOwnUserData();
        // at least ID and Username are mandatory
        if(!isset($responseData['id']) || !isset($responseData['username'])){
            return FALSE;
        }

        return $responseData;
    }

    // This function should not be necessary - problem is decoding the response tailored for facebook in original package, we need to json_decode here
    /**
     * @param string $grantType One of this' interface GRANT_TYPE_* constants
     * @param array $additionalParameters Additional parameters for the request
     * @return mixed
     * @throws \Flowpack\OAuth2\Client\Exception
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
     */
    protected function requestAccessToken($grantType, $additionalParameters = array()) {
        $parameters = array(
            'grant_type' => $grantType,
            'client_id' => $this->clientIdentifier,
            'client_secret' => $this->clientSecret
        );
        $parameters = Arrays::arrayMergeRecursiveOverrule($parameters, $additionalParameters, FALSE, FALSE);

        $request = Request::create(new Uri($this->endpointUri), 'POST', $parameters);
        $request->setHeader('Content-Type', 'application/x-www-form-urlencoded');

        $response = $this->requestEngine->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            throw new OAuth2Exception(sprintf('The response when requesting the access token was not as expected, code and message was: %d %s', $response->getStatusCode(), $response->getContent()), 1383749757);
        }

        $responseComponents = json_decode($response->getContent(),true);

        return $responseComponents['access_token'];
    }
}
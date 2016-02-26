<?php
namespace Weissheiten\OAuth2\ClientInstagram\Utility;

/*                                                                                      *
 * This script belongs to the TYPO3 Flow package "Weissheiten.OAuth2.ClientInstagram".  *
 *                                                                                      */
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Http\Client\CurlEngine;
use TYPO3\Flow\Http\Client\RequestEngineInterface;
use TYPO3\Flow\Http\Request;
use TYPO3\Flow\Http\Uri;
use TYPO3\Flow\Object\DependencyInjection\DependencyProxy;
use Flowpack\OAuth2\Client\Exception as OAuth2Exception;

/**
 * @Flow\Scope("singleton")
 */
class InstagramApiClient
{
    /**
     * @var RequestEngineInterface
     */
    protected $requestEngine;
    /**
     * @var string
     */
    protected $endpoint = 'https://api.instagram.com/v1';
    /**
     * @var string
     */
    protected $appSecret;
    /**
     * The access token to use for the request.
     *
     * @var string
     */
    protected $currentAccessToken;

    /**
     * @Flow\Inject
     * @var \TYPO3\Flow\Log\SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     */
    public function initializeObject() {
        if (($this->requestEngine instanceof DependencyProxy
                && $this->requestEngine->_getClassName() === 'TYPO3\Flow\Http\Client\CurlEngine')
            || $this->requestEngine instanceof CurlEngine) {
            $this->requestEngine->setOption(CURLOPT_CAINFO, FLOW_PATH_PACKAGES . 'Application/Flowpack.OAuth2.Client/Resources/Private/cacert.pem');
            $this->requestEngine->setOption(CURLOPT_SSL_VERIFYPEER, TRUE);
        }
    }

    /**
     * @param string $method
     * @return bool returns the users own data or null if access was not possible
     */
    public function getOwnUserData($method = 'GET'){
        $response = $this->query('/users/self');
        if ($response->getStatusCode() !== 200) {
            $this->securityLogger->log(new OAuth2Exception(sprintf('The response was not of type 200 but gave code and error %d "%s"', $response->getStatusCode(), $response), 1456487579));
            return null;
        }
        else{
            return json_decode($response->getContent(),true)['data'];
        }
    }

    /**
     * @param string $resource
     * @param string $method
     * @return \TYPO3\Flow\Http\Response
     */
    public function query($resource, $method = 'GET') {
        $uri = new Uri($this->endpoint . $resource);
        parse_str((string)$uri->getQuery(), $query);
        $query['access_token'] = $this->currentAccessToken;
        $query['appsecret_proof'] = hash_hmac('sha256', $this->currentAccessToken, $this->appSecret);
        $uri->setQuery(http_build_query($query));
        $request = Request::create($uri, $method);
        $response = $this->requestEngine->sendRequest($request);
        return $response;
    }
    /**
     * @param string $currentAccessToken
     */
    public function setCurrentAccessToken($currentAccessToken) {
        $this->currentAccessToken = $currentAccessToken;
    }
}
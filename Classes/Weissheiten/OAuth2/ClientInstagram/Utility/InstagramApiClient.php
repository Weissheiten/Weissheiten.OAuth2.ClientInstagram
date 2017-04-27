<?php
namespace Weissheiten\OAuth2\ClientInstagram\Utility;

/*                                                                                      *
 * This script belongs to the TYPO3 Flow package "Weissheiten.OAuth2.ClientInstagram".  *
 *                                                                                      */
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Client\CurlEngine;
use Neos\Flow\Http\Client\RequestEngineInterface;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Uri;
use Neos\Flow\ObjectManagement\DependencyInjection\DependencyProxy;
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
     * @var \Neos\Flow\Log\SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     */
    public function initializeObject() {
        if (($this->requestEngine instanceof DependencyProxy
                && $this->requestEngine->_getClassName() === 'Neos\Flow\Http\Client\CurlEngine')
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
        try{
            // will throw a 404 error if the user is not logged in, we expect this to happen so we don't log this
            return $this->query('/users/self')['data'];
        }
        catch(OAuth2Exception $e){
            return false;
        }
    }

    /**
     * Generate a sig for secure API calls
     *
     * @param $params
     * @return string
     */
    private function generate_sig($relEndpoint, $params) {
        $sig = $relEndpoint;
        ksort($params);
        foreach ($params as $key => $val) {
            $sig .= "|$key=$val";
        }
        return hash_hmac('sha256', $sig, $this->appSecret, false);
    }

    /**
     * @param string $resource
     * @param array $requestArguments
     * @param string $method
     * @return mixed
     * @throws OAuth2Exception
     */
    public function query($resource, $requestArguments = array(), $method = 'GET') {
        $requestArguments['access_token'] = $this->currentAccessToken;
        $requestArguments['sig'] = $this->generate_sig($resource, $requestArguments);

        // test the secure API call by getting information of the own user - scope: basic (also available in sandbox mode)
        $request = Request::create(new Uri($this->endpoint . $resource . "?" . http_build_query($requestArguments)));

        $response = $this->requestEngine->sendRequest($request);
        $responseContent = $response->getContent();

        if ($response->getStatusCode() !== 200) {
            $this->securityLogger->log('Error in Instagram Query: '.$responseContent);
            throw new OAuth2Exception(sprintf('The response was not of type 200 but gave code and error %d "%s"', $response->getStatusCode(), $responseContent), 1455261376);
        }

        return json_decode($responseContent,true);
    }
    /**
     * @param string $currentAccessToken
     */
    public function setCurrentAccessToken($currentAccessToken) {
        $this->currentAccessToken = $currentAccessToken;
    }

    /**
     * Searches instagram for results having a specific hashtag before min_tag_id or after max_tag_id
     * Returns a number of results equal to $count
     *
     * @param string $tag
     * @param int $count
     * @param string $max_tag_id
     * @return mixed
     * @throws OAuth2Exception
     */
    public function searchByTag($tag, $count = 10, $max_tag_id = null){
        $requestArguments = array('count' => $count);

        if($max_tag_id!==null && $max_tag_id!==''){
            $requestArguments['max_tag_id'] = $max_tag_id;
        }

        return $this->query('/tags/'.$tag.'/media/recent', $requestArguments);
    }
}
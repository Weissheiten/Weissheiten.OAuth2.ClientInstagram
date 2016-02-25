<?php
namespace Weissheiten\OAuth2\ClientInstagram\Provider;

/*                                                                                      *
 * This script belongs to the TYPO3 Flow package "Weissheiten.OAuth2.ClientInstagram".  *
 *                                                                                      */

use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Flowpack\OAuth2\Client\Provider\AbstractClientProvider;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Log\SecurityLoggerInterface;
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

/**
 */
class InstagramProvider extends AbstractClientProvider {

    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     * @Flow\Inject
     * @var \TYPO3\Flow\Security\AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var \TYPO3\Flow\Security\Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var \Weissheiten\OAuth2\ClientInstagram\Endpoint\InstagramTokenEndpoint
     */
    protected $instagramTokenEndpoint;

    /**
     * Tries to authenticate the given token. Sets isAuthenticated to TRUE if authentication succeeded.
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws \TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException
     * @return void
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof AbstractClientToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1383754993);
        }

        $credentials = $authenticationToken->getCredentials();

        // There is no way to validate the Token or check the scopes at the moment apart from "trying" (and possibly receiving an access denied)
        // we could check the validity of the Token and the scopes here in the future when Instagram provides that

        // Only check if an access Token is present at this time and do a single test call
        if(isset($credentials['accessToken']) && $credentials['accessToken']!==NULL){
            // check if a secure request is possible (https://www.instagram.com/developer/secure-api-requests/)
            $userInfo = $this->instagramTokenEndpoint->validateSecureRequestCapability($credentials['accessToken']);

            if($userInfo===FALSE){
                $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                $this->securityLogger->log('A secure call to the API with the provided accessToken and clientSecret was not possible', LOG_NOTICE);
                return FALSE;
            }
        }

        // From here, we surely know the user is considered authenticated against the remote service,
        // yet to check if there is an immanent account present.
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        /** @var $account \TYPO3\Flow\Security\Account */
        $account = NULL;
        $providerName = $this->name;
        $accountRepository = $this->accountRepository;
        $this->securityContext->withoutAuthorizationChecks(function() use ($userInfo, $providerName, $accountRepository, &$account) {
            $account = $accountRepository->findByAccountIdentifierAndAuthenticationProviderName($userInfo['id'], $providerName);
        });
        if ($account === NULL) {
            $account = new Account();
            $account->setAccountIdentifier($userInfo['id']);
            $account->setAuthenticationProviderName($providerName);
            $this->accountRepository->add($account);
        }

        $authenticationToken->setAccount($account);
        // the access token is valid for an "undefined time" according to instagram (so we cannot know when the user needs to log in again)
        $account->setCredentialsSource($credentials['accessToken']);
        $this->accountRepository->update($account);
    }

    /**
     * Returns the class names of the tokens this provider is responsible for.
     *
     * @return array The class name of the token this provider is responsible for
     */
    public function getTokenClassNames() {
        return array('Weissheiten\OAuth2\ClientInstagram\Token\InstagramToken');
    }
}
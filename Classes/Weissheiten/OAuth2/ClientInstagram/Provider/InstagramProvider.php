<?php
namespace Weissheiten\OAuth2\ClientInstagram\Provider;

/*                                                                                      *
 * This script belongs to the TYPO3 Flow package "Weissheiten.OAuth2.ClientInstagram".  *
 *                                                                                      */

use Flowpack\OAuth2\Client\Exception;
use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Flowpack\OAuth2\Client\Provider\AbstractClientProvider;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\SecurityLoggerInterface;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Party\Domain\Service\PartyService;

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
     * @var \Neos\Flow\Security\AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Security\Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var \Weissheiten\OAuth2\ClientInstagram\Endpoint\InstagramTokenEndpoint
     */
    protected $instagramTokenEndpoint;

    /**
     * @Flow\Inject
     * @var PartyService
     */
    protected $partyService;

    /**
     * @var \Neos\Neos\Domain\Service\UserService
     * @Flow\Inject
     */
    protected $userService;

    /**
     * @Flow\Inject
     * @var PersistenceManagerInterface
     */
    protected $persistenceManager;


    /**
     * Tries to authenticate the given token. Sets isAuthenticated to TRUE if authentication succeeded.
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws \Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException
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
\Neos\Flow\var_dump($credentials);
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
        else{

        }

        // From here, we surely know the user is considered authenticated against the remote service,
        // yet to check if there is an immanent account present.
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        /** @var $account \Neos\Flow\Security\Account */
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

        // check if a user is already attached to this account
        if($this->partyService->getAssignedPartyOfAccount($account)===null || count($this->partyService->getAssignedPartyOfAccount($account)) < 1){
            $user = $this->userService->getCurrentUser();
            if($user!==null){
                $user->addAccount($account);
                $this->userService->updateUser($user);
                $this->persistenceManager->whitelistObject($user);
            }
            else{
                $this->securityLogger->logException(new Exception("The InstagramProvider was unable to determine the backend user, make sure the configuration Neos.Neos:Backend requestPattern matches the Instagram Controller and the authentication strategy is set to 'atLeastOne' Token"));
            }
        }

        // persistAll is called automatically at the end of this function, account gets whitelisted to allow
        // persisting for an object thats tinkered with via a GET request
        $this->persistenceManager->whitelistObject($account);
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
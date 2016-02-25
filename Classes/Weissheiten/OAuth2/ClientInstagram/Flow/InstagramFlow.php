<?php
namespace Weissheiten\OAuth2\ClientInstagram\Flow;

/*                                                                                      *
 * This script belongs to the TYPO3 Flow package "Weissheiten.OAuth2.ClientInstagram".  *
 */

use Flowpack\OAuth2\Client\Exception\InvalidPartyDataException;
use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Flowpack\OAuth2\Client\Flow\AbstractFlow;
use Flowpack\OAuth2\Client\Flow\FlowInterface;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Policy\PolicyService;
use TYPO3\Flow\Validation\ValidatorResolver;
use TYPO3\Party\Domain\Model\ElectronicAddress;
use TYPO3\Party\Domain\Model\Person;
use TYPO3\Party\Domain\Model\PersonName;
use TYPO3\Party\Domain\Repository\PartyRepository;

class InstagramFlow extends AbstractFlow implements FlowInterface{
    /**
     * @Flow\Inject
     * @var \TYPO3\Flow\Security\AccountRepository
     */
    protected $accountRepository;
    /**
     * @Flow\Inject
     * @var \Weissheiten\OAuth2\ClientInstagram\Utility\InstagramApiClient
     */
    protected $instagramApiClient;
    /**
     * @Flow\Inject
     * @var PartyRepository
     */
    protected $partyRepository;

    /**
     * @var \TYPO3\Party\Domain\Service\PartyService
     * @Flow\Inject
     */
    protected $partyService;

    /**
     * @var \TYPO3\Neos\Domain\Service\UserService
     * @Flow\Inject
     */
    protected $userService;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;
    /**
     * @Flow\Inject
     * @var ValidatorResolver
     */
    protected $validatorResolver;

    /**
     * Will contain the user data given by the remote authentication service.
     * @var array
     */
    protected $authenticationServicesUserData = array();

    /**
     * @var array
     */
    protected $tokenForeignAccounts = array();

    /**
     * @param Account $account
     * @return void
     */
    public function attachAccountToBackendParty(Account $account){
        $user = $this->userService->getCurrentUser();
        \TYPO3\Flow\var_dump($user);
        \TYPO3\Flow\var_dump($account->getAccountIdentifier());
        $user->addAccount($account);
    }

    /**
     * @param Account $instagramAccount
     * @return \TYPO3\Party\Domain\Model\AbstractParty;
     */
    public function verifyPartyForAccount(Account $instagramAccount){
        if($this->partyService->getAssignedPartyOfAccount($instagramAccount)===NULL){
            $this->attachAccountToBackendParty($instagramAccount);
        }
    }

    /**
     * @return \TYPO3\Flow\Security\Account
     */
    public function getInstagramAccountHavingParty(){
        foreach($this->userService->getCurrentUser()->getAccounts() as $account){
            if($account->getAuthenticationProviderName==='InstagramOAuth2Provider'){
                return $account;
            }
        }
        return NULL;
    }

    /**
     * @param AbstractClientToken $token
     * @return TokenInterface
     */
    public function getTokenOfForeignAccountOf(AbstractClientToken $token) {
        $foreignAccount = $this->getForeignAccountFor($token);
        /** @var $token TokenInterface */
        foreach ($this->securityContext->getAuthenticationTokens() as $token) {
            if ($token->getAccount() === $foreignAccount) {
                return $token;
            }
        }
        return NULL;
    }
    /**
     * @param AbstractClientToken $token
     * @return Account
     */
    public function getForeignAccountFor(AbstractClientToken $token) {
        if (!array_key_exists((string)$token, $this->tokenForeignAccounts)) {
            if (!isset($this->authenticationServicesUserData[(string)$token])) {
                $this->initializeUserData($token);
            }

            $this->tokenForeignAccounts[(string)$token] = $this->accountRepository->findOneByAccountIdentifier($this->authenticationServicesUserData[(string)$token]['email']);
        }
        return $this->tokenForeignAccounts[(string)$token];
    }

    /**
     * @param TokenInterface $foreignAccountToken
     * @param AbstractClientToken $possibleOAuthTokenAuthenticatedWithoutParty
     */
    public function setPartyOfAuthenticatedTokenAndAttachToAccountFor(TokenInterface $foreignAccountToken, AbstractClientToken $possibleOAuthTokenAuthenticatedWithoutParty) {
        $oauthAccount = $possibleOAuthTokenAuthenticatedWithoutParty->getAccount();
        // TODO: this must be properly specifiable (the Roles to add)
        #$oauthAccount->setRoles();

        // deprecated Version
        //$oauthAccount->setParty($foreignAccountToken->getAccount()->getParty());
        // new implementation
        $this->partyService->assignAccountToParty($oauthAccount,$this->partyService->getAssignedPartyOfAccount($foreignAccountToken));
        $this->accountRepository->update($oauthAccount);
    }

    /**
     * @param AbstractClientToken $token
     * @throws InvalidPartyDataException
     */
    public function createPartyAndAttachToAccountFor(AbstractClientToken $token) {
        $userData = $this->authenticationServicesUserData[(string)$token];
        $party = new Person();
        $party->setName(new PersonName('', $userData['first_name'], '', $userData['last_name']));
        // Todo: this is not covered by the Person implementation, we should have a solution for that
        #$party->setBirthDate(\DateTime::createFromFormat('!m/d/Y', $userData['birthday'], new \DateTimeZone('UTC')));
        #$party->setGender(substr($userData['gender'], 0, 1));
        $electronicAddress = new ElectronicAddress();
        $electronicAddress->setType(ElectronicAddress::TYPE_EMAIL);

        $electronicAddress->setIdentifier($userData['email']);
        $party->addElectronicAddress($electronicAddress);
        $partyValidator = $this->validatorResolver->getBaseValidatorConjunction('TYPO3\Party\Domain\Model\Person');
        $validationResult = $partyValidator->validate($party);
        if ($validationResult->hasErrors()) {
            throw new InvalidPartyDataException('The created party does not satisfy the requirements', 1384266207);
        }
        $account = $token->getAccount();

        // assign the newly created party to the account
        $this->partyService->assignAccountToParty($account,$party);

        $account->setParty($party);
        // TODO: this must be properly specifiable (the Roles to add)
        #$account->setRoles();
        $this->accountRepository->update($account);
        $this->partyRepository->add($party);
    }

    /**
     * Returns the access token of the according token
     * @param AbstractClientToken $token
     *
     * @return string
     */
    public function getTokenUserData(AbstractClientToken $token){
        if (!isset($this->authenticationServicesUserData[(string)$token])) {
            $this->initializeUserData($token);
        }
        return $this->authenticationServicesUserData[(string)$token];
    }

    /**
     * Returns the token class name this flow is responsible for
     * @return string
     */
    public function getTokenClassName() {
        return 'Weissheiten\OAuth2\ClientInstagram\Token\InstagramToken';
    }

    /**
     * @param AbstractClientToken $token
     */
    protected function initializeUserData(AbstractClientToken $token) {
        $credentials = $token->getCredentials();
        $this->instagramApiClient->setCurrentAccessToken($credentials['accessToken']);
        $content = $this->instagramApiClient->query('/users/self')->getContent();
        $this->authenticationServicesUserData[(string)$token] = json_decode($content, TRUE)['data'];
    }

}
<?php
namespace Weissheiten\OAuth2\ClientInstagram\Controller;
/*                                                                                  *
 * This script belongs to the TYPO3 Flow package "Weissheiten.Neos.Instagram".      *
 *                                                                                  *
 *                                                                                  *
 * Redistribution and use in source and binary forms, with or without               *
 * modification, are not permitted.                                                 *
 *                                                                                  */
use Doctrine\ORM\Mapping as ORM;
use Neos\Flow\Annotations as Flow;
use Neos\Error\Messages\Message;
use Neos\Flow\Mvc\Exception\InvalidActionNameException;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Authentication\Controller\AbstractAuthenticationController;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Flowpack\OAuth2\Client\Exception\InvalidPartyDataException;

use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Weissheiten\OAuth2\ClientInstagram\Flow\InstagramFlow;
use Neos\Party\Domain\Service\PartyService;

/**
 * LoginController controller
 */
class AuthenticationController extends AbstractAuthenticationController {

    /**
     * @Flow\Inject
     * @var \Neos\Flow\I18n\Translator
     */
    protected $translator;

    /**
     * @Flow\Inject
     * @var \Weissheiten\OAuth2\ClientInstagram\Flow\InstagramFlow
     */
    protected $authenticationFlow;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Security\AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var \Neos\Neos\Domain\Repository\UserRepository
     */
    protected $userRepository;

    /**
     * @var \Neos\Flow\Security\Context
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @var \Neos\Neos\Domain\Service\UserService
     * @Flow\Inject
     */
    protected $userService;



    /**
     * @Flow\Inject
     * @var PartyService
     */
    protected $partyService;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Log\SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     * In this case, an authentication has successfully been conducted and it's upon us
     * to find out which authentication provider has been used and whether there is a
     * reusable and therefore re-assignable party or not.
     *
     * Note: It occurred that $this->request->getReferringRequest() threw an exception
     * if the referrer internal arguments stuff is present, but not set (empty). In such a
     * case Neos\Flow\Mvc\Exception\InvalidActionNameException('The action name must not be an empty string.', 1289472991)
     * was thrown and the redirect was not possible.
     *
     * @param \Neos\Flow\Mvc\ActionRequest $originalRequest The request that was intercepted by the security framework, NULL if there was none
     * @return string
     */
    protected function onAuthenticationSuccess(\Neos\Flow\Mvc\ActionRequest $originalRequest = NULL) {
/*
        // check if there is an unassigned authentication token
        $possibleOAuthTokenAuthenticatedWithoutParty = $this->authenticationFlow->getChargedAuthenticatedTokenHavingNoPartyAttached();

        if ($possibleOAuthTokenAuthenticatedWithoutParty !== NULL) {
            // retrieve the UserData from instagram
            $userdata = $this->authenticationFlow->getTokenUserData($possibleOAuthTokenAuthenticatedWithoutParty);

            if(isset($userdata['id']) && $userdata['id']!==NULL) {
                // does an account for this Token already exist
                $instagramAccount = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($userdata['id'],'InstagramOAuth2Provider');

                // \Neos\Flow\var_dump($this->accountRepository->findAll()->toArray());

                if($instagramAccount===NULL){
                    $instagramAccount = new \Neos\Flow\Security\Account();
                    $instagramAccount->setAccountIdentifier($userdata['id']);
                    $instagramAccount->setAuthenticationProviderName('InstagramOAuth2Provider');
                    //$this->accountRepository->add($instagramAccount);

                }

                // Associate this new Account with the token
                $possibleOAuthTokenAuthenticatedWithoutParty->setAccount($instagramAccount);
                // Associate the Account with the current BE party
                $user = $this->userService->getCurrentUser();
                $user->addAccount($instagramAccount);
                $this->userRepository->update($user);

            }
            else{
                $this->securityLogger->logException(new Exception("Could not retrieve UserData from Instagram in Weissheiten.Neos.InstagramMedia"));
            }
        }
        else{
            try {
                if ($originalRequest !== NULL) {
                    $requestToRedirect = $originalRequest;
                } elseif ($this->request->getInternalArgument('__fromClientUri') !== NULL) {
                    // the login was initiated from a specific page - we send the user back there
                    $this->redirectToUri($this->request->getInternalArgument('__fromClientUri'));
                } elseif ($this->request->getReferringRequest() !== NULL) {
                    $requestToRedirect = $this->request->getReferringRequest();
                }
                if (isset($requestToRedirect)
                    && $requestToRedirect->getHttpRequest()->getHeader('X-Requested-With') !== 'XMLHttpRequest'	// it's possible that accidentally XMLHttpRequest requests were intercepted, and we don't want to redirect to them ofc
                    && !in_array($requestToRedirect->getControllerName(), array('Authentication', 'Landing'))) {
                    $this->redirectToRequest($requestToRedirect);
                }
            } catch (InvalidActionNameException $exception) {
                $this->systemLogger->logException($exception);
            }
        }
*/
        $this->redirect('index','backend\module','Neos.Neos',array('module' => 'management/InstagramMedia'));
    }

    /**
     * @param AuthenticationRequiredException $exception
     */
    protected function onAuthenticationFailure(AuthenticationRequiredException $exception = NULL) {
        /** @var $token TokenInterface */
        foreach ($this->securityContext->getAuthenticationTokens() as $token) {
            if ($token instanceof AbstractClientToken && $token->getAuthenticationStatus() === TokenInterface::WRONG_CREDENTIALS) {
                $this->addFlashMessage('An error occurred during your log in. Please make sure you\'re granting all required permissions because this is need for the Instagram Client to run.', 'Wrong input', Message::SEVERITY_ERROR, array(), 1383817435);
                $this->forward('login');
                break;
            }
        }
        $this->addFlashMessage('The e-mail address or the password have not been entered correctly.', 'Wrong input', Message::SEVERITY_ERROR, array(), 1371119714);
        $this->forward('index');
    }

    /**
     * @return void
     */
    public function logoutAction() {
        parent::logoutAction();
        $this->redirect('index', 'Landing', NULL, array('loggedOut' => TRUE));
    }
}
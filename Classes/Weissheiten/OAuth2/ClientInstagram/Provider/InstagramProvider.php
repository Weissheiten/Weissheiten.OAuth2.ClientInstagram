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
        // Dev Version - set Standard to AuthenticationNeeded
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
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
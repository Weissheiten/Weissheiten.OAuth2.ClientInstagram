<?php
namespace Weissheiten\OAuth2\ClientInstagram\Token;

/*                                                                                      *
 * This script belongs to the TYPO3 Flow package "Weissheiten.OAuth2.ClientInstagram".  *
 *                                                                                      */

use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Flowpack\OAuth2\Client\Provider\AbstractClientProvider;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\SecurityLoggerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

/**
 */
class InstagramToken extends AbstractClientToken {
}
